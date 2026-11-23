# Konfiguracja providera Azure dla Terraform
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
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

provider "azurerm" {
  features {}
}

# 1. Grupa zasobów (Resource Group)
resource "azurerm_resource_group" "rg" {
  name     = var.resource_group_name
  location = var.location
  tags = {
    Project = "Master-Thesis-ARM64"
    Owner   = "Piotr"
  }
}

# 2. Sieć wirtualna i podsieć
resource "azurerm_virtual_network" "vnet" {
  name                = "vnet-thesis-arm64"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_subnet" "subnet" {
  name                 = "snet-thesis-arm64"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}

# 3. Publiczny adres IP
resource "azurerm_public_ip" "pip" {
  name                = "pip-thesis-cobalt100"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

# 4. Sieciowa grupa bezpieczeństwa (Firewall - tylko SSH)
resource "azurerm_network_security_group" "nsg" {
  name                = "nsg-thesis-arm64"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  security_rule {
    name                       = "Allow-SSH"
    priority                   = 1000
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# 5. Karta sieciowa (NIC)
resource "azurerm_network_interface" "nic" {
  name                = "nic-thesis-cobalt100"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.pip.id
  }
}

resource "azurerm_network_interface_security_group_association" "nic_nsg" {
  network_interface_id      = azurerm_network_interface.nic.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

# 6. Automatyczny klucz SSH RSA (Azure wymaga kluczy RSA dla maszyn wirtualnych)
resource "tls_private_key" "ssh_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "local_file" "private_key" {
  content         = tls_private_key.ssh_key.private_key_pem
  filename        = "${path.module}/id_cobalt_rsa"
  file_permission = "0600"
}

# 7. Maszyna wirtualna ARM64 — Microsoft Cobalt 100 (Neoverse-N2)
resource "azurerm_linux_virtual_machine" "vm" {
  name                  = "vm-thesis-cobalt100"
  location              = azurerm_resource_group.rg.location
  resource_group_name   = azurerm_resource_group.rg.name
  network_interface_ids = [azurerm_network_interface.nic.id]
  size                  = var.vm_size
  admin_username        = var.admin_username

  admin_ssh_key {
    username   = var.admin_username
    public_key = tls_private_key.ssh_key.public_key_openssh
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
    disk_size_gb         = 30
  }

  # Ubuntu 24.04 LTS Noble dla architektury ARM64
  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server-arm64"
    version   = "latest"
  }

  # Automatyczna instalacja zależności przez cloud-init
  custom_data = filebase64("${path.module}/cloud-init.yaml")

  tags = {
    Project     = "Master-Thesis"
    Architecture = "ARM64-Cobalt100"
  }
}

# 8. Automatyczne wyłączanie maszyny codziennie o 21:00 (bezpiecznik finansowy)
resource "azurerm_dev_test_global_vm_shutdown_schedule" "auto_shutdown" {
  virtual_machine_id = azurerm_linux_virtual_machine.vm.id
  location           = azurerm_resource_group.rg.location
  enabled            = true

  daily_recurrence_time = "2100"
  timezone              = "Central European Standard Time"

  notification_settings {
    enabled = false
  }
}

