use super::*;
use sigil_multimodal::ArtifactRef;

#[test]
fn document_adapter_extracts_plain_text() {
    let text = b"Hello, world!\nThis is a test document.";
    let adapter = DocumentAdapter;
    let report = adapter
        .perceive(&ArtifactRef {
            source_id: "doc-1".to_string(),
            bytes: text,
            media_type: Some("text/plain".to_string()),
        })
        .expect("perceive");

    assert_eq!(report.source_id, "doc-1");
    assert_eq!(report.artifact_digest.len(), 96);
    assert!(report
        .properties
        .iter()
        .any(|(k, _)| k.ends_with(".format")));
    let text_channel = report
        .channels
        .iter()
        .find(|c| c.channel_kind == ChannelKind::TextLayer)
        .expect("text layer channel");
    assert!(text_channel.content.contains("Hello, world!"));
    assert!(!text_channel.truncated);
}

#[test]
fn document_adapter_extracts_markdown() {
    let md = b"# Title\n\nSome **bold** text.";
    let adapter = DocumentAdapter;
    let report = adapter
        .perceive(&ArtifactRef {
            source_id: "doc-2".to_string(),
            bytes: md,
            media_type: Some("text/markdown".to_string()),
        })
        .expect("perceive");

    let text_channel = report
        .channels
        .iter()
        .find(|c| c.channel_kind == ChannelKind::TextLayer)
        .expect("text layer");
    assert!(text_channel.content.contains("# Title"));
}

#[test]
fn document_adapter_extracts_pdf_text() {
    // Minimal PDF with a text string.
    let pdf = b"%PDF-1.0\n1 0 obj\n<< /Type /Catalog >>\nendobj\nBT /F1 12 Tf (Hello PDF) Tj ET";
    let adapter = DocumentAdapter;
    let report = adapter
        .perceive(&ArtifactRef {
            source_id: "pdf-1".to_string(),
            bytes: pdf,
            media_type: Some("application/pdf".to_string()),
        })
        .expect("perceive");

    let text_channel = report
        .channels
        .iter()
        .find(|c| c.channel_kind == ChannelKind::TextLayer)
        .expect("pdf text channel");
    assert!(
        text_channel.content.contains("Hello PDF"),
        "extracted text should contain 'Hello PDF': {}",
        text_channel.content
    );
}

#[test]
fn document_adapter_rejects_binary() {
    let adapter = DocumentAdapter;
    let err = adapter
        .perceive(&ArtifactRef {
            source_id: "bin-1".to_string(),
            bytes: &[0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA],
            media_type: Some("application/octet-stream".to_string()),
        })
        .expect_err("binary should fail");
    assert_eq!(
        err,
        PerceptionError::UnsupportedMediaType("application/octet-stream".to_string())
    );
}

#[test]
fn document_adapter_auto_detects_text() {
    let text = b"Just some plain text without a media type.";
    let adapter = DocumentAdapter;
    let report = adapter
        .perceive(&ArtifactRef {
            source_id: "doc-3".to_string(),
            bytes: text,
            media_type: None,
        })
        .expect("perceive");

    assert_eq!(report.media_type, "text/plain");
    assert!(report
        .channels
        .iter()
        .any(|c| c.channel_kind == ChannelKind::TextLayer));
}

#[test]
fn document_adapter_auto_detects_pdf() {
    let pdf = b"%PDF-1.0\nBT (test) Tj ET";
    let adapter = DocumentAdapter;
    let report = adapter
        .perceive(&ArtifactRef {
            source_id: "doc-4".to_string(),
            bytes: pdf,
            media_type: None,
        })
        .expect("perceive");

    assert_eq!(report.media_type, "application/pdf");
}

#[test]
fn pdf_extraction_uses_lopdf_for_valid_documents() {
    // Create a valid PDF using lopdf's own API, then verify the
    // adapter extracts text through the lopdf path (not fallback).
    let pdf_bytes = create_minimal_pdf_with_text("Hello from lopdf");
    assert!(!pdf_bytes.is_empty(), "generated PDF should not be empty");

    let adapter = DocumentAdapter;
    let report = adapter
        .perceive(&ArtifactRef {
            source_id: "pdf-lopdf-1".to_string(),
            bytes: &pdf_bytes,
            media_type: Some("application/pdf".to_string()),
        })
        .expect("perceive");

    let text_channel = report
        .channels
        .iter()
        .find(|c| c.channel_kind == ChannelKind::TextLayer)
        .expect("pdf text channel should exist for valid PDF");
    assert!(
        text_channel.content.contains("Hello from lopdf"),
        "lopdf extraction should find the text: {}",
        text_channel.content
    );
    // lopdf path should not be truncated for a valid PDF.
    assert!(!text_channel.truncated, "valid PDF should not be truncated");
}

#[test]
fn pdf_extraction_falls_back_for_invalid_documents() {
    // Not a valid PDF — lopdf will fail, fallback string scanner runs.
    let fake_pdf = b"%PDF-1.0\nBT (Fallback text) Tj ET";
    let adapter = DocumentAdapter;
    let report = adapter
        .perceive(&ArtifactRef {
            source_id: "pdf-fallback-1".to_string(),
            bytes: fake_pdf,
            media_type: Some("application/pdf".to_string()),
        })
        .expect("perceive");

    // Fallback should still extract the string literal.
    let text_channel = report
        .channels
        .iter()
        .find(|c| c.channel_kind == ChannelKind::TextLayer)
        .expect("fallback should still produce a text channel");
    assert!(
        text_channel.content.contains("Fallback text"),
        "fallback should extract string literal: {}",
        text_channel.content
    );
    // Fallback path sets truncated = true.
    assert!(
        text_channel.truncated,
        "fallback path should set truncated = true"
    );
}

/// Create a minimal valid PDF using lopdf's API, serialized to bytes.
fn create_minimal_pdf_with_text(text: &str) -> Vec<u8> {
    use lopdf::{
        content::{Content, Operation},
        dictionary, Document, Object, Stream,
    };
    let mut doc = Document::with_version("1.4");
    let pages_id = doc.add_object(dictionary! {
        "Type" => "Pages", "Count" => 0, "Kids" => Vec::<Object>::new(),
    });
    let font_id = doc.add_object(dictionary! {
        "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
    });
    let content = Content {
        operations: vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 12.into()]),
            Operation::new("Td", vec![10.into(), 80.into()]),
            Operation::new("Tj", vec![Object::string_literal(text)]),
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
    let pages = doc.get_object_mut(pages_id).unwrap().as_dict_mut().unwrap();
    pages.set("Kids", vec![Object::Reference(page_id)]);
    pages.set("Count", 1);
    let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    doc.trailer.set("Root", catalog_id);
    let mut buf = Vec::new();
    doc.save_to(&mut buf).expect("serialize PDF");
    buf
}
