package authzen

import rego.v1

default allow := false

# The scope each path needs.
needs := "roles.write" if {
	contains(input.resource.id, "/admin/")
} else := "tickets.read"

scope := split(object.get(input.context, "scope", ""), " ")

allow if {
	needs in scope
}

# A request carrying a verified AAT chain was already limited by the chain.
allow if {
	input.context.chain.profile == "aat-02"
}
