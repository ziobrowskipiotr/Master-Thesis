variable "project_id" {
  description = "ID projektu w Google Cloud Platform (GCP Project ID)"
  type        = string
  default     = "thesis-arm64"
}

variable "region" {
  description = "Region GCP (europe-west4 - Holandia)"
  type        = string
  default     = "europe-west4"
}

variable "zone" {
  description = "Strefa w wybranym regionie (europe-west4-b ma wsparcie dla Google Axion C4A)"
  type        = string
  default     = "europe-west4-b"
}

variable "machine_type" {
  description = "Typ instancji ARM64: Google Axion (ARMv9-A / Neoverse-V2) c4a-standard-4"
  type        = string
  default     = "c4a-standard-4"
}

variable "boot_disk_type" {
  description = "Typ dysku (seria C4A wymaga hyperdisk-balanced)"
  type        = string
  default     = "hyperdisk-balanced"
}

variable "admin_username" {
  description = "Nazwa użytkownika administracyjnego (SSH)"
  type        = string
  default     = "piotr"
}

variable "boot_disk_size_gb" {
  description = "Rozmiar dysku rozruchowego w GB"
  type        = number
  default     = 30
}
