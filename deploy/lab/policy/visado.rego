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

