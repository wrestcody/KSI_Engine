variable "vanguard_agent_api_url" {
  description = "The URL of the Vanguard Agent API endpoint."
  type        = string
}

variable "vanguard_api_key" {
  description = "The API key for the Vanguard Agent API."
  type        = string
  sensitive   = true
}

variable "remediation_path" {
  description = "The URL to the remediation playbook."
  type        = string
  default     = "https://github.com/wrestcody/Praetorium_Nexus/blob/main/remediation_playbooks/s3_public_access_fix.tf"
}
