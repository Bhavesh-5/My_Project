import ast

class CustomSecurityScanner(ast.NodeVisitor):
    def __init__(self):
        self.issues = []

    def visit_Assign(self, node):
        # Rule: Hardcoded credentials in variable assignment
        if isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id.lower()
            if var_name in ['password', 'passwd', 'pwd', 'secret', 'token', 'key']:
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, (str, int, bool)):
                    self.issues.append({
                        'message': f"Hardcoded credential found: '{var_name}'",
                        'severity': 'High',
                        'category': 'A2: Broken Authentication'
                    })

        # Rule: Hardcoded URLs/IPs
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            val = node.value.value
            if 'http://' in val or 'https://' in val or self._is_ip_address(val):
                self.issues.append({
                    'message': f"Hardcoded URL or IP found: '{val}'",
                    'severity': 'Low',
                    'category': 'A6: Security Misconfiguration'
                })

        self.generic_visit(node)

    def visit_Dict(self, node):
        # Rule: Hardcoded credentials in dictionaries
        for key, value in zip(node.keys, node.values):
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                key_name = key.value.lower()
                if key_name in ['password', 'passwd', 'pwd', 'secret', 'token', 'key']:
                    if isinstance(value, ast.Constant) and isinstance(value.value, (str, int, bool)):
                        self.issues.append({
                            'message': f"Hardcoded credential in dictionary: '{key_name}'",
                            'severity': 'High',
                            'category': 'A2: Broken Authentication'
                        })

    def visit_Call(self, node):
        # Rule: eval()
        if isinstance(node.func, ast.Name) and node.func.id == 'eval':
            self.issues.append({
                'message': "Use of eval() is dangerous",
                'severity': 'High',
                'category': 'A1: Injection'
            })

        # Rule: exec()
        if isinstance(node.func, ast.Name) and node.func.id == 'exec':
            self.issues.append({
                'message': "Use of exec() is dangerous",
                'severity': 'High',
                'category': 'A1: Injection'
            })

        # Rule: os.system()
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == 'system':
                self.issues.append({
                    'message': "Use of os.system() can lead to command injection",
                    'severity': 'High',
                    'category': 'A1: Injection'
                })

        # Rule: yaml.load() without safe loader
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == 'load':
                if hasattr(node.func.value, 'id') and node.func.value.id == 'yaml':
                    self.issues.append({
                        'message': "Use of yaml.load() without safe loader is unsafe",
                        'severity': 'High',
                        'category': 'A8: Deserialization'
                    })

        # Rule: subprocess with shell=True
        for kw in node.keywords:
            if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                self.issues.append({
                    'message': "subprocess call with shell=True is dangerous",
                    'severity': 'High',
                    'category': 'A1: Injection'
                })

        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name == 'pickle':
                self.issues.append({
                    'message': "Use of pickle module can lead to insecure deserialization",
                    'severity': 'Medium',
                    'category': 'A8: Deserialization'
                })
            if alias.name == 'subprocess':
                self.issues.append({
                    'message': "Use of subprocess module requires caution",
                    'severity': 'Medium',
                    'category': 'A1: Injection'
                })

    def visit_ImportFrom(self, node):
        if node.module == 'hashlib':
            for alias in node.names:
                if alias.name in ['md5', 'sha1']:
                    self.issues.append({
                        'message': f"Weak hash function used: {alias.name}",
                        'severity': 'Medium',
                        'category': 'A3: Sensitive Data Exposure'
                    })

    def _is_ip_address(self, s):
        parts = s.split('.')
        return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

def run_custom_scan(file_path):
    try:
        with open(file_path, 'r') as f:
            tree = ast.parse(f.read(), filename=file_path)
        scanner = CustomSecurityScanner()
        scanner.visit(tree)
        return scanner.issues
    except Exception as e:
        return [{
            'message': f"Custom scan failed: {str(e)}",
            'severity': 'Error',
            'category': 'N/A'
        }]