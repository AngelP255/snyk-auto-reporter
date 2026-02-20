import subprocess
import json
import os

class SnykScanner:
    def __init__(self, project_path):
        self.project_path = project_path

    def _run_command(self, cmd_list):
        try:
            result = subprocess.run(cmd_list, capture_output=True, text=True)
            if result.stdout:
                start_index = result.stdout.find('{')
                if start_index != -1:
                    return json.loads(result.stdout[start_index:])
            return None
        except Exception as e:
            print(f"Error al ejecutar comando: {e}")
            return None

    def run_scan(self):
        print(f"--- Escaneando librerías en: {self.project_path} ---")
        lib_data = self._run_command(['snyk', 'test', '--json', self.project_path])

        print(f"--- Escaneando código fuente en: {self.project_path} ---")
        code_data = self._run_command(['snyk', 'code', 'test', '--json', self.project_path])

        if not lib_data and not code_data:
            return None
        return (lib_data, code_data)

    def analyze_results(self, raw_data):
        lib_data, code_data = raw_data
        
        summary = {
            "project_name": os.path.basename(self.project_path) or "Proyecto Auditado",
            "lib_vulns": 0,
            "code_issues": 0,
            "severity_levels": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "lib_details": [],  
            "code_details": []  
        }

        
        if lib_data:
            projects = lib_data if isinstance(lib_data, list) else [lib_data]
            summary["project_name"] = projects[0].get("projectName", summary["project_name"])
            for project in projects:
                vulns = project.get("vulnerabilities", [])
                summary["lib_vulns"] += len(vulns)
                for v in vulns:
                    sev = v.get("severity", "low").lower()
                    if sev in summary["severity_levels"]:
                        summary["severity_levels"][sev] += 1
                    
                   
                    paquete = v.get("packageName", "Desconocido")
                    titulo = v.get("title", "Sin título")
                    summary["lib_details"].append(f"[{sev.upper()}] Paquete '{paquete}': {titulo}")

        
        if code_data:
            runs = code_data.get("runs", [])
            if runs:
                issues = runs[0].get("results", [])
                summary["code_issues"] += len(issues)
                for i in issues:
                    sev = "low"
                    level = i.get("level", "note").lower()
                    if level == "error": sev = "high"
                    elif level == "warning": sev = "medium"
                    
                    props = i.get("properties", {})
                    if "severity" in props:
                        sev = props["severity"].lower()
                        
                    if sev in summary["severity_levels"]:
                        summary["severity_levels"][sev] += 1
                    
                   
                    regla = i.get("ruleId", "Regla desconocida")
                    archivo = "Archivo desconocido"
                    locaciones = i.get("locations", [])
                    if locaciones:
                        archivo = locaciones[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "Archivo desconocido")
                    
                    summary["code_details"].append(f"[{sev.upper()}] {regla} en: {archivo}")

        return summary