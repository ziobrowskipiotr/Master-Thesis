# Konfiguracja providera Google Cloud dla Terraform
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

# 1. Sieć VPC i podsieć
resource "google_compute_network" "vpc" {
  name                    = "vpc-thesis-arm64"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet" {
  name          = "snet-thesis-arm64"
  ip_cidr_range = "10.0.1.0/24"
  region        = var.region
  network       = google_compute_network.vpc.id
}

# 2. Reguła Firewall (dostęp SSH z zewnątrz)
resource "google_compute_firewall" "allow_ssh" {
  name    = "fw-thesis-allow-ssh"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["ssh-allowed"]
}

# 3. Automatyczne wygenerowanie pary kluczy SSH
resource "tls_private_key" "ssh_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "local_file" "private_key" {
  content         = tls_private_key.ssh_key.private_key_pem
  filename        = "${path.module}/id_gcp_rsa"
  file_permission = "0600"
}

# 4. Maszyna wirtualna ARM64 w GCP
resource "google_compute_instance" "vm" {
  name         = "vm-thesis-arm64-gcp"
  machine_type = var.machine_type
  zone         = var.zone

  tags = ["ssh-allowed"]

  boot_disk {
    initialize_params {
      # Ubuntu 24.04 LTS Noble dla architektury ARM64
      image = "ubuntu-os-cloud/ubuntu-2404-lts-arm64"
      size  = var.boot_disk_size_gb
      type  = var.boot_disk_type
    }
  }

  network_interface {
    network    = google_compute_network.vpc.id
    subnetwork = google_compute_subnetwork.subnet.id

    access_config {
      # Pusty blok access_config przydziela publiczny adres IP
    }
  }

  metadata = {
    ssh-keys  = "${var.admin_username}:${tls_private_key.ssh_key.public_key_openssh}"
    user-data = file("${path.module}/cloud-init.yaml")
  }

  labels = {
    project      = "master-thesis"
    architecture = "arm64"
  }

  service_account {
    scopes = ["cloud-platform"]
  }
}
