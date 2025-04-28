package pdfG;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Paragraph;

import java.io.ByteArrayOutputStream;

public class BlobToPdfGenerator {

    // Static method to generate and return the PDF as a byte array
    public static byte[] generatePdf(String message) {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        try {
            // Create a PdfWriter that writes to the ByteArrayOutputStream
            PdfWriter writer = new PdfWriter(byteStream);

            // Create a PdfDocument object with the writer
            PdfDocument pdfDoc = new PdfDocument(writer);

            // Create a Document object for adding elements like paragraphs
            Document document = new Document(pdfDoc);

            // Add the provided message as a paragraph in the document
            document.add(new Paragraph(message));

            // Close the document to finalize the PDF
            document.close();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

        // Return the PDF as a byte array
        return byteStream.toByteArray();
    }
}
