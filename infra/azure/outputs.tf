output "public_ip" {
  description = "Publiczny adres IP maszyny wirtualnej Cobalt 100"
  value       = azurerm_public_ip.pip.ip_address
}

output "ssh_command" {
  description = "Gotowe polecenie do połączenia przez SSH"
  value       = "ssh -i id_cobalt_rsa -o StrictHostKeyChecking=no ${var.admin_username}@${azurerm_public_ip.pip.ip_address}"
}

output "verify_cpu_command" {
  description = "Polecenie sprawdzające flagi MTE, PAC i BTI w procesorze maszyny"
  value       = "ssh -i id_cobalt_rsa -o StrictHostKeyChecking=no ${var.admin_username}@${azurerm_public_ip.pip.ip_address} 'lscpu; grep -E (mte|paca|pacg|bti) /proc/cpuinfo'"
}

