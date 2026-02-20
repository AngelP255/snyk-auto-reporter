from fpdf import FPDF
from datetime import datetime
import os
import textwrap  

class SecurityReporter:
    def __init__(self, output_folder="reports"):
        self.output_folder = output_folder
        if not os.path.exists(self.output_folder):
            os.makedirs(self.output_folder)

    def _limpiar_texto(self, texto):
        """
        Usa textwrap para forzar el corte de línea estricto.
        Si hay una palabra de 200 letras, la cortará sin piedad.
        """
        texto_seguro = str(texto).encode('latin-1', 'replace').decode('latin-1')
        
      
        return textwrap.fill(texto_seguro, width=85, break_long_words=True)

    def generate_pdf(self, stats):
        pdf = FPDF() 
        pdf.add_page()
        
       
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "Reporte de Auditoria de Seguridad", ln=True, align="C")
        pdf.set_font("Arial", "", 10)
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M")
        pdf.cell(0, 10, f"Generado el: {date_str} | Proyecto: {stats.get('project_name', '')}", ln=True, align="C")
        pdf.ln(10)
        
        
        pdf.set_font("Arial", "B", 12)
        pdf.set_text_color(0, 0, 255)
        pdf.cell(0, 10, "1. Seguridad de Librerias (Dependencias Open Source)", ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Arial", "", 11)
        pdf.cell(0, 10, f"Vulnerabilidades encontradas en librerias: {stats.get('lib_vulns', 0)}", ln=True)
        pdf.ln(5)

        pdf.set_font("Arial", "B", 12)
        pdf.set_text_color(0, 128, 0)
        pdf.cell(0, 10, "2. Analisis de Codigo Fuente (Snyk Code)", ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Arial", "", 11)
        pdf.cell(0, 10, f"Problemas detectados en la logica del codigo: {stats.get('code_issues', 0)}", ln=True)
        pdf.ln(10)
        
      
        pdf.set_font("Arial", "B", 11)
        pdf.cell(0, 10, "Resumen de Severidades Totales:", ln=True)
        for level, count in stats.get('severity_levels', {}).items():
            pdf.cell(60, 10, f"{level.capitalize()}: {count}", border=1, ln=True)
        
        pdf.ln(15)


        if stats.get('lib_details') or stats.get('code_details'):
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 10, "--- Anexo: Detalle de Vulnerabilidades ---", ln=True, align="C")
            pdf.ln(5)

        if stats.get('lib_details'):
            pdf.set_font("Arial", "B", 12)
            pdf.set_text_color(0, 0, 255)
            pdf.cell(0, 10, "Detalles en Librerias:", ln=True)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Arial", "", 10)
            for detalle in stats['lib_details']:
               
                pdf.multi_cell(0, 6, f"* {self._limpiar_texto(detalle)}")
                pdf.ln(2) 
            pdf.ln(6)

        if stats.get('code_details'):
            pdf.set_font("Arial", "B", 12)
            pdf.set_text_color(0, 128, 0)
            pdf.cell(0, 10, "Detalles en Codigo Fuente:", ln=True)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Arial", "", 10)
            for detalle in stats['code_details']:
                pdf.multi_cell(0, 6, f"* {self._limpiar_texto(detalle)}")
                pdf.ln(2)

        filename = f"reporte_detallado_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
        path = os.path.join(self.output_folder, filename)
        pdf.output(path)
        return path