variable "vanguard_agent_api_url" {
  description = "The URL of the Vanguard Agent API endpoint."
  type        = string
}

variable "vanguard_api_key" {
  description = "The API key for the Vanguard Agent API."
  type        = string
  sensitive   = true
}
