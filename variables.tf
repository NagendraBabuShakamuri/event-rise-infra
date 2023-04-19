variable "region" {
  type = string
}

variable "aws_profile" {
  type = string
}

variable "cidr_block" {
  type = string
}

variable "public_subnets" {
  type = number
}

variable "private_subnets" {
  type = number
}

variable "db_name" {
  type = string
}

variable "db_username" {
  type = string
}

variable "db_password" {
  type = string
}

variable "domain" {
  type = string
}

variable "CLIENT_ID" {
    type= string
}

variable "CLIENT_SECRET" {
    type= string
}