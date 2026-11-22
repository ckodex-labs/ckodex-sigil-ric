//! Pillow-compatible image resampling on 8-bit RGB (the semantics of Pillow's
//! `libImaging/Resample.c` and its nearest-neighbour resize).
//!
//! Model processors that use the "slow" PIL path (transformers'
//! `Qwen2VLImageProcessor` in 4.x) resize with Pillow, so a profile that
//! claims to produce the model's view must reproduce Pillow bit for bit.
//! Being close to Pillow is not enough: the parity gate is SHA-384 equality
//! with the reference bytes.
//!
//! Bicubic follows Pillow's convolution:
//! - filter a = −0.5, support 2;
//! - on downscale the support widens by the scale factor;
//! - per output pixel, weights are normalized to sum 1 in f64, then rounded
//!   to signed 22-bit fixed point (away from zero at .5);
//! - each channel accumulates from 2^21 and is shifted right by 22, then
//!   clamped to 0..=255;
//! - the passes are separable with an 8-bit intermediate. The order of the
//!   two passes changes the bytes, and it depends on the Pillow version:
//!   12.3.0 always runs horizontal first (read in its `Resample.c`), 13.0.0
//!   does not (see [`pillow13_pass_order`]).
//!
//! Nearest reproduces Pillow's scale-affine path: pixel-centre sampling with
//! the source position accumulated by repeated addition.

/// Row-major 8-bit RGB pixels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rgb8 {
    pub width: usize,
    pub height: usize,
    pub data: Vec<u8>,
}

impl Rgb8 {
    fn pixel(&self, x: usize, y: usize) -> [u8; 3] {
        let i = (y * self.width + x) * 3;
        [self.data[i], self.data[i + 1], self.data[i + 2]]
    }
}

/// Fixed-point precision of the 8-bit convolution, as in Pillow.
const PRECISION_BITS: u32 = 32 - 8 - 2;
const BICUBIC_A: f64 = -0.5;
const BICUBIC_SUPPORT: f64 = 2.0;
const CHANNELS: usize = 3;

fn bicubic(x: f64) -> f64 {
    let x = x.abs();
    if x < 1.0 {
        ((BICUBIC_A + 2.0) * x - (BICUBIC_A + 3.0)) * x * x + 1.0
    } else if x < 2.0 {
        (((x - 5.0) * x + 8.0) * x - 4.0) * BICUBIC_A
    } else {
        0.0
    }
}

/// Per output index: the first source index, the tap count, and fixed-point
/// weights.
struct Coefficients {
    ksize: usize,
    bounds: Vec<(usize, usize)>,
    weights: Vec<i64>,
}

fn coefficients(in_size: usize, out_size: usize) -> Coefficients {
    let scale = in_size as f64 / out_size as f64;
    let filter_scale = scale.max(1.0);
    let support = BICUBIC_SUPPORT * filter_scale;
    // Pillow multiplies by the reciprocal; dividing differs in the last ulp
    // and can flip a fixed-point rounding.
    let inverse_scale = 1.0 / filter_scale;
    let ksize = support.ceil() as usize * 2 + 1;
    let mut bounds = Vec::with_capacity(out_size);
    let mut weights = vec![0_i64; out_size * ksize];
    for xx in 0..out_size {
        let center = (xx as f64 + 0.5) * scale;
        // C `(int)` casts truncate toward zero; `as i64` does the same.
        let xmin = ((center - support + 0.5) as i64).max(0) as usize;
        let xmax = ((center + support + 0.5) as i64).min(in_size as i64) as usize - xmin;
        let raw: Vec<f64> = (0..xmax)
            .map(|x| bicubic(((x + xmin) as f64 - center + 0.5) * inverse_scale))
            .collect();
        let total: f64 = raw.iter().sum();
        for (slot, w) in weights[xx * ksize..].iter_mut().zip(&raw) {
            let w = if total == 0.0 { *w } else { w / total };
            let fixed = w * f64::from(1_u32 << PRECISION_BITS);
            *slot = if w < 0.0 {
                (fixed - 0.5) as i64
            } else {
                (fixed + 0.5) as i64
            };
        }
        bounds.push((xmin, xmax));
    }
    Coefficients {
        ksize,
        bounds,
        weights,
    }
}

fn clip8(accumulator: i64) -> u8 {
    (accumulator >> PRECISION_BITS).clamp(0, 255) as u8
}

const ROUNDING: i64 = 1 << (PRECISION_BITS - 1);

fn convolve(taps: impl Iterator<Item = ([u8; 3], i64)>) -> [u8; 3] {
    let mut acc = [ROUNDING; CHANNELS];
    for (pixel, weight) in taps {
        for (sum, value) in acc.iter_mut().zip(pixel) {
            *sum += i64::from(value) * weight;
        }
    }
    acc.map(clip8)
}

fn horizontal(
    src: &Rgb8,
    rows: std::ops::Range<usize>,
    out_width: usize,
    c: &Coefficients,
) -> Rgb8 {
    let mut data = Vec::with_capacity(out_width * rows.len() * CHANNELS);
    for y in rows.clone() {
        for (xx, (xmin, n)) in c.bounds.iter().enumerate() {
            let k = &c.weights[xx * c.ksize..xx * c.ksize + n];
            data.extend(convolve((0..*n).map(|i| (src.pixel(xmin + i, y), k[i]))));
        }
    }
    Rgb8 {
        width: out_width,
        height: rows.len(),
        data,
    }
}

fn vertical(src: &Rgb8, offset: usize, out_height: usize, c: &Coefficients) -> Rgb8 {
    let mut data = Vec::with_capacity(src.width * out_height * CHANNELS);
    for (yy, (ymin, n)) in c.bounds.iter().enumerate().take(out_height) {
        let k = &c.weights[yy * c.ksize..yy * c.ksize + n];
        for x in 0..src.width {
            data.extend(convolve(
                (0..*n).map(|i| (src.pixel(x, ymin - offset + i), k[i])),
            ));
        }
    }
    Rgb8 {
        width: src.width,
        height: out_height,
        data,
    }
}

/// Which separable pass runs first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PassOrder {
    HorizontalFirst,
    VerticalFirst,
}

/// Pillow 13.0.0's pass order for a bicubic resize, where it is known.
///
/// Observed by running Pillow 13.0.0 on 360 sizes across three source shapes
/// (validated, not read from its source): horizontal first unless the image
/// grows horizontally and shrinks vertically, which runs vertical first.
/// When both axes shrink Pillow picks either order and no size or cost rule
/// fitted the observations, so the order is unknown: `None`. When only one
/// pass runs the order does not matter.
#[must_use]
pub fn pillow13_pass_order(
    in_width: usize,
    in_height: usize,
    width: usize,
    height: usize,
) -> Option<PassOrder> {
    if width == in_width || height == in_height {
        return Some(PassOrder::HorizontalFirst);
    }
    match (width > in_width, height > in_height) {
        (_, true) => Some(PassOrder::HorizontalFirst),
        (true, false) => Some(PassOrder::VerticalFirst),
        (false, false) => None,
    }
}

/// Pillow `Image.resize(size, BICUBIC)` with the default box, passes in the
/// given order.
#[must_use]
pub fn resize_bicubic(src: &Rgb8, width: usize, height: usize, order: PassOrder) -> Rgb8 {
    match order {
        PassOrder::HorizontalFirst => horizontal_first(src, width, height),
        PassOrder::VerticalFirst => {
            let stage = if height == src.height {
                src.clone()
            } else {
                vertical(src, 0, height, &coefficients(src.height, height))
            };
            if width == src.width {
                return stage;
            }
            let rows = 0..stage.height;
            horizontal(&stage, rows, width, &coefficients(src.width, width))
        }
    }
}

fn horizontal_first(src: &Rgb8, width: usize, height: usize) -> Rgb8 {
    let horiz = coefficients(src.width, width);
    let vert = coefficients(src.height, height);
    let first_row = vert.bounds.first().map_or(0, |(start, _)| *start);
    let last_row = vert
        .bounds
        .last()
        .map_or(src.height, |(start, n)| start + n);
    let (stage, offset) = if width == src.width {
        (src.clone(), 0)
    } else {
        (
            horizontal(src, first_row..last_row, width, &horiz),
            first_row,
        )
    };
    if height == src.height {
        return stage;
    }
    vertical(&stage, offset, height, &vert)
}

/// Pillow `Image.resize(size, NEAREST)`, which for a pure scale runs
/// `ImagingScaleAffine`: the source coordinate starts at `0.5 · scale` and
/// is advanced by repeated addition of `scale` (floating-point accumulation,
/// reproduced as such), truncated to an index.
#[must_use]
pub fn resize_nearest(src: &Rgb8, width: usize, height: usize) -> Rgb8 {
    let table = |in_size: usize, out_size: usize| {
        let scale = in_size as f64 / out_size as f64;
        let mut position = scale * 0.5;
        (0..out_size)
            .map(|_| {
                let index = (position as usize).min(in_size - 1);
                position += scale;
                index
            })
            .collect::<Vec<usize>>()
    };
    let (xs, ys) = (table(src.width, width), table(src.height, height));
    let mut data = Vec::with_capacity(width * height * CHANNELS);
    for sy in &ys {
        for sx in &xs {
            data.extend(src.pixel(*sx, *sy));
        }
    }
    Rgb8 {
        width,
        height,
        data,
    }
}
