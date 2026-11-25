package main

import rego.v1

# ==============================================================================
# Politica OpenVEX Audit (Rego v1) - Esqueleto Guiado
# Valida conformidade estrutural e obrigatoriedade de justificativas OpenVEX.
# Teste com: conftest test attestations/vex_customizado.openvex.json -p policies/openvex_audit.rego
# ==============================================================================

# Regra 1 (Exemplo resolvido): Exigir schema oficial OpenVEX v0.2.0 no @context
deny contains msg if {
	ctx := object.get(input, "@context", "")
	ctx != "https://openvex.dev/ns/v0.2.0"
	msg := sprintf("VIOLACAO OPENVEX: @context invalido ('%v'). Esperado: 'https://openvex.dev/ns/v0.2.0'.", [ctx])
}

# Regra 2: Bloquear caso o array 'statements' esteja ausente ou vazio.
deny contains msg if {
	stmts := object.get(input, "statements", [])
	count(stmts) == 0
	msg := "VIOLACAO OPENVEX: O documento OpenVEX deve conter pelo menos 1 statement de triagem."
}

# Regra 3: Exigir justificativa preenchida para todo statement 'not_affected'.
deny contains msg if {
	some stmt in object.get(input, "statements", [])
	stmt.status == "not_affected"
	just := object.get(stmt, "justification", "")
	regex.match("^($|TODO)", just)
	vulnerability := object.get(stmt, "vulnerability", {})
	name := object.get(vulnerability, "name", "desconhecida")
	msg := sprintf("VIOLACAO OPENVEX: Statement para '%v' marcado como 'not_affected' sem justificativa oficial valida.", [name])
}
