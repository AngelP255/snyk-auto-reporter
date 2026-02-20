import os
import sys


sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scanner import SnykScanner
from reporter import SecurityReporter

def main():
    print("--- Snyk Auto-Reporter ---")
    ruta_bruta = input("Introduce o arrastra la ruta del proyecto a escanear: ").strip()
    
   
    ruta_limpia = ruta_bruta.replace("'", "").replace('"', "").replace("\\", "")
    ruta_limpia = os.path.expanduser(ruta_limpia)

  
    if not os.path.exists(ruta_limpia):
        print(f"Error: La ruta '{ruta_limpia}' no existe.")
        print("Revisa que la carpeta esté correcta.")
        return


    scanner = SnykScanner(ruta_limpia)
    raw_data = scanner.run_scan()
    
   
    if raw_data:
        stats = scanner.analyze_results(raw_data)
        
        reporter = SecurityReporter()
        pdf_path = reporter.generate_pdf(stats)
        
        print("\n" + "="*40)
        print("🚀 ¡AUDITORÍA COMPLETADA CON ÉXITO!")
        print(f"📂 Proyecto: {stats['project_name']}")
        print(f"📄 Reporte: {pdf_path}")
        print("="*40)
    else:
        print("\n" + "!"*40)
        print("Error: No se pudieron obtener datos de Snyk.")
        print("Asegúrate de que el proyecto tenga dependencias instaladas o código válido.")
        print("!"*40)

if __name__ == "__main__":
    main()