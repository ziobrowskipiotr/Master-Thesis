variable "location" {
  description = "Region Azure (Cobalt 100 jest szeroko dostępny m.in. w Szwecji i Holandii)"
  type        = string
  default     = "swedencentral"
}

variable "resource_group_name" {
  description = "Nazwa grupy zasobów"
  type        = string
  default     = "rg-thesis-arm64-cobalt"
}

variable "vm_size" {
  description = "Rozmiar maszyny ARM64 (Cobalt v7 / ARMv9: Standard_D2ps_v7 to 2 vCPU, 8 GB RAM)"
  type        = string
  default     = "Standard_D2ps_v7"
}

variable "admin_username" {
  description = "Użytkownik administracyjny na maszynie wirtualnej"
  type        = string
  default     = "piotr"
}

