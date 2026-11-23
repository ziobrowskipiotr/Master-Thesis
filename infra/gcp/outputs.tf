output "public_ip" {
  description = "Publiczny adres IP maszyny wirtualnej ARM64 w GCP"
  value       = google_compute_instance.vm.network_interface[0].access_config[0].nat_ip
}

output "ssh_command" {
  description = "Polecenie SSH do bezpośredniego połączenia z maszyną"
  value       = "ssh -i id_gcp_rsa -o StrictHostKeyChecking=no ${var.admin_username}@${google_compute_instance.vm.network_interface[0].access_config[0].nat_ip}"
}

output "verify_cpu_command" {
  description = "Polecenie sprawdzające flagi MTE, PAC i BTI w procesorze maszyny"
  value       = "ssh -i id_gcp_rsa -o StrictHostKeyChecking=no ${var.admin_username}@${google_compute_instance.vm.network_interface[0].access_config[0].nat_ip} 'lscpu; grep -E (mte|paca|pacg|bti) /proc/cpuinfo'"
}
