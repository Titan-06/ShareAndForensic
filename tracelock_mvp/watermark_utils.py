"""
TraceLock - Invisible Forensic Watermarking Module
===================================================
This module handles dynamic, covert forensic watermarking of PDF documents
at the moment of decryption using PyMuPDF.

Steganographic Multi-Layer Architecture:
Layer 1: Invisible Text Overlay (ISO 32000-1 render_mode=3 "Neither fill nor stroke",
         opacity 0.0, microscopic font size across all pages).
Layer 2: Standard PDF Metadata dictionary injection (Keywords / Subject).
Layer 3: Low-Level Catalog Dictionary Direct Object Key (TraceLockForensicSession).

This redundancy guarantees that even if a leaker strips metadata or modifies page layouts,
the traitor tracing session ID can still be reliably extracted.
"""

import re
import json
from typing import Optional, Dict, Any, Tuple
import pymupdf as fitz  # Standard PyMuPDF import


WATERMARK_PREFIX = "TRACELOCK_FORENSIC_TAG"


def embed_invisible_watermark(
    pdf_bytes: bytes,
    session_id: str,
    user_id: str,
    timestamp: str
) -> bytes:
    """
    Dynamically inject covert forensic markers into a PDF document.
    
    :param pdf_bytes: Decrypted plaintext PDF bytes.
    :param session_id: Unique cryptographically bound tracking session ID.
    :param user_id: Identifier of the authorized decryptor (e.g., 'Alice').
    :param timestamp: ISO timestamp of decryption event.
    :return: Pristine-looking watermarked PDF bytes.
    """
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    
    forensic_payload = f"{WATERMARK_PREFIX}:SESSION_ID={session_id}:USER={user_id}:TS={timestamp}"
    
    # Layer 1: Inject invisible text on every page
    for page_idx in range(len(doc)):
        page = doc[page_idx]
        rect = page.rect
        
        # We inject covert text at safe coordinates (top margin and bottom corner)
        # Using render_mode=3 (PDF Invisible Text Operator '3 Tr')
        # Combined with fill_opacity=0.0 and white color
        point_top = fitz.Point(10, 15)
        point_bottom = fitz.Point(10, rect.height - 15)
        
        # Insert invisible forensic string
        page.insert_text(
            point_top,
            forensic_payload,
            fontsize=1.0,
            color=(1, 1, 1),
            fill_opacity=0.0,
            render_mode=3
        )
        page.insert_text(
            point_bottom,
            f"TL:{session_id}",
            fontsize=1.0,
            color=(1, 1, 1),
            fill_opacity=0.0,
            render_mode=3
        )

    # Layer 2: PDF Document Metadata Dictionary
    metadata = doc.metadata or {}
    existing_keywords = metadata.get("keywords", "") or ""
    tl_keyword = f"TRACELOCK:{session_id}"
    
    if tl_keyword not in existing_keywords:
        new_keywords = f"{existing_keywords} {tl_keyword}".strip()
    else:
        new_keywords = existing_keywords
        
    metadata["keywords"] = new_keywords
    metadata["subject"] = f"TraceLock Forensic Session [{session_id}]"
    doc.set_metadata(metadata)
    
    # Layer 3: Low-Level Catalog XREF injection
    try:
        catalog_xref = doc.pdf_catalog()
        doc.xref_set_key(catalog_xref, "TraceLockForensicSession", f"'{session_id}'")
        doc.xref_set_key(catalog_xref, "TraceLockDecryptor", f"'{user_id}'")
    except Exception as e:
        print(f"[watermark_utils] Catalog xref injection note: {e}")

    # Serialize PDF with clean garbage collection and deflation
    output_bytes = doc.tobytes(garbage=3, deflate=True)
    doc.close()
    return output_bytes


def extract_watermark(pdf_bytes: bytes) -> Optional[Dict[str, Any]]:
    """
    Extract invisible forensic watermarks from a suspect / leaked PDF.
    Searches across Page Text streams, PDF Metadata, and low-level Catalog XREFs.
    
    :param pdf_bytes: Binary bytes of the suspect PDF.
    :return: Forensic extraction details dictionary or None if no watermark found.
    """
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    except Exception as e:
        raise ValueError(f"Failed to parse PDF document: {e}")
        
    session_id: Optional[str] = None
    extracted_user: Optional[str] = None
    extracted_timestamp: Optional[str] = None
    detected_layers = []
    pages_found = []
    
    # Regex patterns for forensic token parsing
    tag_regex = re.compile(
        r"TRACELOCK_FORENSIC_TAG:SESSION_ID=([A-Za-z0-9_\-]+):USER=([A-Za-z0-9_\-]+):TS=([^\s]+)"
    )
    simple_tag_regex = re.compile(r"TL:([A-Za-z0-9_\-]+)")
    meta_regex = re.compile(r"TRACELOCK:([A-Za-z0-9_\-]+)")

    # 1. Search Page Content Streams (Layer 1)
    for idx in range(len(doc)):
        page = doc[idx]
        text = page.get_text("text") or ""
        
        match = tag_regex.search(text)
        if match:
            session_id = match.group(1)
            extracted_user = match.group(2)
            extracted_timestamp = match.group(3)
            detected_layers.append("Invisible Page Text (Layer 1)")
            pages_found.append(idx + 1)
            break
            
        simple_match = simple_tag_regex.search(text)
        if simple_match:
            session_id = simple_match.group(1)
            detected_layers.append("Invisible Page Micro-Tag (Layer 1b)")
            pages_found.append(idx + 1)
            break

    # 2. Search PDF Metadata (Layer 2)
    metadata = doc.metadata or {}
    keywords = metadata.get("keywords", "") or ""
    subject = metadata.get("subject", "") or ""
    
    meta_match = meta_regex.search(keywords) or meta_regex.search(subject)
    if meta_match:
        if not session_id:
            session_id = meta_match.group(1)
        detected_layers.append("Document Metadata Dictionary (Layer 2)")

    # 3. Search PDF Catalog Direct Key (Layer 3)
    try:
        catalog_xref = doc.pdf_catalog()
        cat_session = doc.xref_get_key(catalog_xref, "TraceLockForensicSession")
        if cat_session and cat_session[0] == "string":
            raw_val = cat_session[1].strip(" '\"()")
            if raw_val:
                if not session_id:
                    session_id = raw_val
                detected_layers.append("Low-Level Catalog Object (Layer 3)")
    except Exception:
        pass

    doc.close()
    
    if not session_id:
        return None
        
    return {
        "session_id": session_id,
        "extracted_user": extracted_user,
        "extracted_timestamp": extracted_timestamp,
        "detection_layers": list(set(detected_layers)),
        "pages_found": pages_found
    }


def create_sample_pdf(title: str, body_text: str) -> bytes:
    """
    Generate a formatted test PDF for air-gapped demonstration and testing.
    """
    doc = fitz.open()
    page = doc.new_page(width=595, height=842) # Standard A4
    
    # Header Banner
    header_rect = fitz.Rect(50, 40, 545, 90)
    page.draw_rect(header_rect, color=(0.1, 0.2, 0.4), fill=(0.93, 0.95, 0.99))
    
    page.insert_text(
        fitz.Point(65, 70),
        "TRACELOCK RESTRICTED DOCUMENT",
        fontsize=14,
        color=(0.1, 0.2, 0.5)
    )
    
    page.insert_text(
        fitz.Point(50, 130),
        title,
        fontsize=18,
        color=(0.1, 0.1, 0.1)
    )
    
    # Body Text
    text_rect = fitz.Rect(50, 160, 545, 750)
    page.insert_textbox(
        text_rect,
        body_text,
        fontsize=11,
        color=(0.2, 0.2, 0.2)
    )
    
    pdf_bytes = doc.tobytes()
    doc.close()
    return pdf_bytes
