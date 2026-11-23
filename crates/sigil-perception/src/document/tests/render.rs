use super::*;

/// Build a valid N-page PDF, one visible line per page.
fn create_multi_page_pdf(pages: &[&str]) -> Vec<u8> {
    use lopdf::{
        Document, Object, Stream,
        content::{Content, Operation},
        dictionary,
    };
    let mut doc = Document::with_version("1.4");
    let pages_id = doc.add_object(dictionary! {
        "Type" => "Pages", "Count" => 0, "Kids" => Vec::<Object>::new(),
    });
    let font_id = doc.add_object(dictionary! {
        "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
    });
    let mut kids = Vec::new();
    for text in pages {
        let content = Content {
            operations: vec![
                Operation::new("BT", vec![]),
                Operation::new("Tf", vec!["F1".into(), 12.into()]),
                Operation::new("Td", vec![10.into(), 80.into()]),
                Operation::new("Tj", vec![Object::string_literal(*text)]),
                Operation::new("ET", vec![]),
            ],
        };
        let content_id = doc.add_object(Stream::new(dictionary! {}, content.encode().unwrap()));
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 200.into()],
            "Contents" => content_id,
            "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
        });
        kids.push(Object::Reference(page_id));
    }
    let count = kids.len();
    let pages = doc.get_object_mut(pages_id).unwrap().as_dict_mut().unwrap();
    pages.set("Kids", kids);
    pages.set("Count", count as i64);
    let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    doc.trailer.set("Root", catalog_id);
    let mut buf = Vec::new();
    doc.save_to(&mut buf).expect("serialize PDF");
    buf
}

/// Write a fake executable that logs its args and emits canned output.
fn fake_binary(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    std::fs::write(&path, body).expect("write fake binary");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    path
}

/// A compare chain over fake binaries: the renderer logs each invocation's
/// args to `log` and emits a canned PNG marker; the OCR ignores the pixels
/// and returns the page's "visible" text.
fn render_compare_adapter(dir: &std::path::Path, log: &std::path::Path) -> DocumentAdapter {
    let renderer = fake_binary(
        dir,
        "render",
        &format!(
            "#!/bin/sh\ncat >/dev/null\necho \"$@\" >> '{}'\nprintf 'PNG'",
            log.display()
        ),
    );
    let ocr = fake_binary(
        dir,
        "ocr",
        "#!/bin/sh\ncat >/dev/null\nprintf 'visible page'",
    );
    DocumentAdapter {
        render_compare: Some(RenderCompare {
            renderer: crate::ExternalPipe::pin(
                renderer,
                vec![
                    "-png".to_string(),
                    "-singlefile".to_string(),
                    "-".to_string(),
                ],
                "fake-render".to_string(),
            )
            .expect("pin renderer"),
            ocr: crate::ExternalOcr::pin(ocr, Vec::new(), "fake-ocr".to_string()).expect("pin ocr"),
        }),
    }
}

#[test]
fn render_compare_renders_every_page() {
    // The page-2-only line in the text layer must surface as divergence.
    let dir = std::env::temp_dir().join(format!("sigil-rc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tempdir");
    let log = dir.join("args.log");
    let adapter = render_compare_adapter(&dir, &log);

    let pdf = create_multi_page_pdf(&["visible page", "hidden line"]);
    let report = adapter
        .perceive(&ArtifactRef {
            source_id: "pdf-2p".to_string(),
            bytes: &pdf,
            media_type: Some("application/pdf".to_string()),
        })
        .expect("perceive");

    let props = |name: &str| {
        report
            .properties
            .iter()
            .find(|(k, _)| k.ends_with(name))
            .map(|(_, v)| v.clone())
    };
    assert_eq!(props("render_compare.pages_rendered").as_deref(), Some("2"));
    assert_eq!(props("render_compare.status").as_deref(), Some("ran"));

    // One renderer invocation per page, each carrying -f N -l N.
    let log_text = std::fs::read_to_string(&log).expect("args log");
    let invocations: Vec<&str> = log_text.lines().collect();
    assert_eq!(invocations.len(), 2, "one render run per page: {log_text}");
    assert!(invocations[0].contains("-f 1") && invocations[1].contains("-f 2"));

    // The text layer carries page 2's line; the render does not.
    let divergence = report
        .channels
        .iter()
        .find(|c| c.channel_kind == ChannelKind::Divergence)
        .expect("divergence channel");
    assert_eq!(divergence.content.trim(), "hidden line");
}
