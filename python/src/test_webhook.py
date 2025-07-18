#!/usr/bin/env python3

from y_sweet_sdk import DocumentManager
from pycrdt import Doc, Text

def test_ysweet_document():
    # Initialize DocumentManager
    dm = DocumentManager("ys://localhost:8080")
    

    # Create or get document and token
    doc_info = dm.get_or_create_doc_and_token("test_document")
    print("Document info:", doc_info)
    
    doc_id = doc_info['docId']
    print(f"Working with document: {doc_id}")
    
    # Get the document as an update
    update = dm.get_doc_as_update(doc_id)
    print(f"Initial update: {update}")
    
    # Create a new Doc object and apply the update
    doc = Doc()
    doc.apply_update(update)
    print(f"Document keys after applying update: {list(doc.keys())}")
    
    # Get or create a "content" Text object
    content = doc.get("content", type=Text)
    print(f"Content object: {content}")
    
    # Insert some text
    content.insert(0, "Hello, Y-Sweet world!")
    print(f"Document items after insert: {dict(doc.items())}")
    
    # Get the update with our changes
    update_back = doc.get_update()
    print(f"Update to send back: {update_back}")
    
    # Apply the update back to the server
    dm.update_doc(doc_id, update_back)
    print("Successfully updated document on server")
    
    # Verify by getting the document again
    verification_update = dm.get_doc_as_update(doc_id)
    verification_doc = Doc()
    verification_doc.apply_update(verification_update)
    verification_content = verification_doc.get("content", type=Text)
    print(f"Verification - content after round trip: '{str(verification_content)}'")

if __name__ == "__main__":
    test_ysweet_document()

