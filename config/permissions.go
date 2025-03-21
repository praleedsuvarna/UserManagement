package config

var Permissions = map[string]map[string]bool{
	"super_admin": {
		"manage_all_organizations": true,
		"manage_users":             true,
		"view_users":               true,
	},
	"admin": {
		"manage_users": true,
		"view_users":   true,
	},
	"user": {
		"view_users": false,
	},
}

// Check if role has permission
func HasPermission(role, permission string) bool {
	perms, exists := Permissions[role]
	if !exists {
		return false
	}
	return perms[permission]
}
