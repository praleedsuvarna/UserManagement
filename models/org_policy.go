package models

type OrganizationPolicy struct {
	OrganizationID string   `bson:"organization_id" json:"organization_id"`
	MaxUsers       int      `bson:"max_users" json:"max_users"`
	AutoApprove    bool     `bson:"auto_approve" json:"auto_approve"`
	AllowedDomains []string `bson:"allowed_domains" json:"allowed_domains"`
}
