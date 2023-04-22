resource "aws_vpc" "dev-vpc" {
  cidr_block = var.cidr_block

  tags = {
    Name = "${var.aws_profile}-vpc"
  }
}

data "aws_availability_zones" "all" {
  state = "available"
}

resource "aws_subnet" "public-subnet" {
  count                   = var.public_subnets
  vpc_id                  = aws_vpc.dev-vpc.id
  cidr_block              = cidrsubnet(var.cidr_block, 8, count.index)
  availability_zone       = element(data.aws_availability_zones.all.names, count.index % length(data.aws_availability_zones.all.names))
  map_public_ip_on_launch = "true"

  tags = {
    Name = "${aws_vpc.dev-vpc.id}-Public subnet ${count.index + 1}"
  }
}

resource "aws_subnet" "private-subnet" {
  count             = var.private_subnets
  vpc_id            = aws_vpc.dev-vpc.id
  cidr_block        = cidrsubnet(var.cidr_block, 4, count.index + 1)
  availability_zone = element(data.aws_availability_zones.all.names, count.index % length(data.aws_availability_zones.all.names))

  tags = {
    Name = "${aws_vpc.dev-vpc.id}-Private subnet ${count.index + 1}"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.dev-vpc.id

  tags = {
    "Name" = "Internet-gateway"
  }
}

resource "aws_route_table" "public-route-table" {
  vpc_id = aws_vpc.dev-vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }
  tags = {
    "Name" = "Public-route-table"
  }
}

resource "aws_route_table" "private-route-table" {
  vpc_id = aws_vpc.dev-vpc.id
  tags = {
    "Name" = "Private-route-table"
  }
}

resource "aws_route_table_association" "public-route-table-association" {
  count          = var.public_subnets
  subnet_id      = aws_subnet.public-subnet[count.index].id
  route_table_id = aws_route_table.public-route-table.id
}

resource "aws_route_table_association" "private-route-table-association" {
  count          = var.private_subnets
  subnet_id      = aws_subnet.private-subnet[count.index].id
  route_table_id = aws_route_table.private-route-table.id
}

resource "aws_security_group" "app-lb-sg" {
  name        = "${var.aws_profile}-app-load-balancer-sg"
  description = "Load balancer security group to allow inbound traffic from the Internet"
  vpc_id      = aws_vpc.dev-vpc.id
  depends_on  = [aws_vpc.dev-vpc]

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.aws_profile}-app-load-balancer-sg"
  }
}

resource "aws_security_group" "frontend-app-sg" {
  name        = "${var.aws_profile}-frontend-app-sg"
  description = "Default security group to allow inbound/outbound from the VPC"
  vpc_id      = aws_vpc.dev-vpc.id
  depends_on  = [aws_vpc.dev-vpc]
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port       = 3006
    to_port         = 3006
    protocol        = "tcp"
    security_groups = [aws_security_group.app-lb-sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.aws_profile}-frontend-app-sg"
  }
}

resource "aws_security_group" "backend-app-sg" {
  name        = "${var.aws_profile}-backend-app-sg"
  description = "Default security group to allow inbound/outbound from the VPC"
  vpc_id      = aws_vpc.dev-vpc.id
  depends_on  = [aws_vpc.dev-vpc]
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.app-lb-sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.aws_profile}-backend-app-sg"
  }
}

resource "aws_security_group" "db-sg" {
  name        = "${var.aws_profile}-database-sg"
  description = "Database security group to allow inbound/outbound from the VPC"
  vpc_id      = aws_vpc.dev-vpc.id
  depends_on  = [aws_vpc.dev-vpc]
  ingress {
    from_port       = 27017
    to_port         = 27017
    protocol        = "tcp"
    security_groups = [aws_security_group.backend-app-sg.id]
  }
  tags = {
    Name = "${var.aws_profile}-database-sg"
  }
}

# Create a DB subnet group
resource "aws_db_subnet_group" "private_db_subnet_group" {
  name       = "private_db_subnet_group"
  subnet_ids = [for s in aws_subnet.public-subnet : s.id]
}

resource "aws_kms_key" "rds_kms_key" {
  description = "My Docdb KMS key"
}

#MongoDB database

resource "aws_docdb_cluster_parameter_group" "example" {
  family      = "docdb4.0"
  name        = "example"
  description = "docdb cluster parameter group"

  parameter {
    name  = "tls"
    value = "disabled"
  }
}

resource "aws_docdb_cluster" "mongodb" {
  cluster_identifier              = "my-mongodb-cluster"
  engine                          = "docdb"
  master_username                 = var.db_username
  master_password                 = var.db_password
  storage_encrypted               = true
  kms_key_id                      = aws_kms_key.rds_kms_key.arn
  db_subnet_group_name            = aws_db_subnet_group.private_db_subnet_group.name
  vpc_security_group_ids          = [aws_security_group.db-sg.id]
  db_cluster_parameter_group_name = aws_docdb_cluster_parameter_group.example.name
  skip_final_snapshot             = true
}

resource "aws_docdb_cluster_instance" "cluster_instances" {
  identifier         = "docdb-cluster-demo"
  cluster_identifier = aws_docdb_cluster.mongodb.id
  instance_class     = "db.t3.medium"
}

#Get the latest AMI.

data "aws_ami" "custom_ami" {
  most_recent = true
  filter {
    name   = "name"
    values = ["info6150*"]
  }
}

# Generate a random name for the S3 bucket.

resource "random_id" "random" {
  byte_length = 4
}

#Create a private S3 bucket.

resource "aws_s3_bucket" "private_bucket" {
  bucket        = "my-${var.aws_profile}-bucket-${random_id.random.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "app" {
  bucket                  = aws_s3_bucket.private_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_acl" "this" {
  bucket = aws_s3_bucket.private_bucket.id
  acl    = "private"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.private_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.private_bucket.id
  rule {
    id     = "transition_to_standard_ia"
    status = "Enabled"
    filter {}
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }
}

# Create an IAM Role for S3 Access.

resource "aws_iam_role" "EC2-EventRise" {
  name = "EC2-EventRise"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# Create an S3 access policy to the above role.

resource "aws_iam_policy" "WebAppS3" {
  name        = "WebAppS3"
  description = "Policy for accessing S3 bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Effect = "Allow"
        Resource = [
          "${aws_s3_bucket.private_bucket.arn}",
          "${aws_s3_bucket.private_bucket.arn}/*"
        ]
      }
    ]
  })
}

# Attach the policy to the created role.

resource "aws_iam_role_policy_attachment" "s3_access_role_attachment" {
  policy_arn = aws_iam_policy.WebAppS3.arn
  role       = aws_iam_role.EC2-EventRise.name
}

resource "aws_iam_role_policy_attachment" "docdb_policy_attachment" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonDocDBFullAccess"
  role       = aws_iam_role.EC2-EventRise.name
}

resource "aws_iam_role_policy_attachment" "s3_policy_attachment" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
  role       = aws_iam_role.EC2-EventRise.name
}

# Application load balancer
resource "aws_lb" "frontend-lb" {
  name               = "${var.aws_profile}-frontend-load-balancer"
  internal           = false
  load_balancer_type = "application"
  subnets            = [for s in aws_subnet.public-subnet : s.id]
  security_groups    = [aws_security_group.app-lb-sg.id]

  tags = {
    Name = "${var.aws_profile}-frontend-load-balancer"
  }
}

resource "aws_lb" "backend-lb" {
  name               = "${var.aws_profile}-backend-load-balancer"
  internal           = false
  load_balancer_type = "application"
  subnets            = [for s in aws_subnet.public-subnet : s.id]
  security_groups    = [aws_security_group.app-lb-sg.id]

  tags = {
    Name = "${var.aws_profile}-backend-load-balancer"
  }
}

# Target group
resource "aws_lb_target_group" "frontend_tg" {
  name        = "frontend-tg"
  port        = 3006
  protocol    = "HTTP"
  vpc_id      = aws_vpc.dev-vpc.id
  target_type = "instance"
  health_check {
    enabled             = true
    interval            = 60
    path                = "/"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 2
    healthy_threshold   = 2
    unhealthy_threshold = 5
  }
}

resource "aws_lb_target_group" "backend_tg" {
  name        = "backend-tg"
  port        = 3000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.dev-vpc.id
  target_type = "instance"
  health_check {
    enabled             = true
    interval            = 60
    path                = "/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 2
    healthy_threshold   = 2
    unhealthy_threshold = 5
  }
}

data "aws_acm_certificate" "frontend_ssl_certificate" {
  domain   = "www.${var.domain}"
  statuses = ["ISSUED"]
}

data "aws_acm_certificate" "backend_ssl_certificate" {
  domain   = "api.${var.domain}"
  statuses = ["ISSUED"]
}

resource "aws_lb_listener" "frontend_listener" {
  load_balancer_arn = aws_lb.frontend-lb.arn
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn   = data.aws_acm_certificate.frontend_ssl_certificate.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.frontend_tg.arn
  }
}

resource "aws_lb_listener" "backend_listener" {
  load_balancer_arn = aws_lb.backend-lb.arn
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn   = data.aws_acm_certificate.backend_ssl_certificate.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.backend_tg.arn
  }
}

# Launch Configuration
resource "aws_launch_template" "frontend_asg_launch_template" {
  name                    = "frontend-asg-launch-config"
  image_id                = data.aws_ami.custom_ami.id
  instance_type           = "t2.micro"
  key_name                = aws_key_pair.ec2keypair.key_name
  ebs_optimized           = false
  disable_api_termination = false

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.frontend-app-sg.id]
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 10
      volume_type           = "gp2"
      delete_on_termination = true
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "Frontend EC2 Instance"
    }
  }

  user_data = base64encode(<<-EOF
    #!/bin/bash   

    echo "[Unit]
    Description=app.js - making your environment variables
    Documentation=https://example.com
    Wants=network-online.target
    After=network-online.target

    [Service]
    Environment="REACT_APP_BASE_URL=https://api.eventrise.me/"
    Environment="REACT_APP_API_SERVER=https://api.eventrise.me"
    Type=simple
    User=ec2-user
    WorkingDirectory=/home/ec2-user/eventrise/
    ExecStart=/usr/bin/npm start
    Restart=on-failure

    [Install]
    WantedBy=multi-user.target" > /etc/systemd/system/eventrise.service

    sudo systemctl daemon-reload
    sudo systemctl enable eventrise.service
    sudo systemctl start eventrise.service
    
  EOF
  )

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_profile.name
  }
}

resource "aws_launch_template" "backend_asg_launch_template" {
  name                    = "backend-asg-launch-config"
  image_id                = data.aws_ami.custom_ami.id
  instance_type           = "t2.micro"
  key_name                = aws_key_pair.ec2keypair.key_name
  ebs_optimized           = false
  disable_api_termination = false

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.backend-app-sg.id]
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 10
      volume_type           = "gp2"
      delete_on_termination = true
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "Backend EC2 Instance"
    }
  }

  user_data = base64encode(<<-EOF
    #!/bin/bash    
    
    echo "[Unit]
    Description=app.js - making your environment variables
    Documentation=https://example.com
    Wants=network-online.target
    After=network-online.target

    [Service]
    Environment="AWS_DEFAULT_REGION=${var.region}"
    Environment="S3_BUCKET=${aws_s3_bucket.private_bucket.id}"
    Environment="MONGO_CONN_STR=mongodb://${var.db_username}:${var.db_password}@${aws_docdb_cluster_instance.cluster_instances.endpoint}:27017/web?retryWrites=false"
    Environment="CLIENT_ID=${var.CLIENT_ID}"
    Environment="CLIENT_SECRET=${var.CLIENT_SECRET}"
    Environment="STRIPE_PUBLISHABLE_KEY=pk_test_51Mxzk4JxhojHtBxQQ2olQn82o3gvqx9UhkUTa9Ek1PBvvV4WLjgongrluAy2pmxJnoobSy0yz68AxBk95lVQNmHZ00bgO5ojnB"
    Environment="STRIPE_SECRET_KEY=sk_test_51Mxzk4JxhojHtBxQCLvUS6MxT4yf5GgqDU6dio05rlmPGvNBoK8XgX1iBG6WnGnPzKkFypQI9WQTtzDbdhLMGJIj00rXRoY1Jy"
    Type=simple
    User=ec2-user
    WorkingDirectory=/home/ec2-user/event-rise-apis/
    ExecStart=/usr/bin/node app.js
    Restart=on-failure

    [Install]
    WantedBy=multi-user.target" > /etc/systemd/system/eventrise_apis.service

    sudo systemctl daemon-reload
    sudo systemctl enable eventrise_apis.service
    sudo systemctl start eventrise_apis.service
    
  EOF
  )

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_profile.name
  }
}

# Auto Scaling Group
resource "aws_autoscaling_group" "frontend_asg" {
  name                = "frontend-asg"
  target_group_arns   = [aws_lb_target_group.frontend_tg.arn]
  vpc_zone_identifier = [for s in aws_subnet.public-subnet : s.id]
  launch_template {
    id      = aws_launch_template.frontend_asg_launch_template.id
    version = "$Latest"
  }
  min_size                  = 1
  max_size                  = 3
  desired_capacity          = 1
  health_check_type         = "ELB"
  health_check_grace_period = 120
  default_cooldown          = 60
  tag {
    key                 = "Name"
    value               = "Frontend EC2 Instance"
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_group" "backend_asg" {
  name                = "backend-asg"
  target_group_arns   = [aws_lb_target_group.backend_tg.arn]
  vpc_zone_identifier = [for s in aws_subnet.public-subnet : s.id]
  launch_template {
    id      = aws_launch_template.backend_asg_launch_template.id
    version = "$Latest"
  }
  min_size                  = 1
  max_size                  = 3
  desired_capacity          = 1
  health_check_type         = "ELB"
  health_check_grace_period = 120
  default_cooldown          = 60
  tag {
    key                 = "Name"
    value               = "Backend EC2 Instance"
    propagate_at_launch = true
  }
}

resource "aws_cloudwatch_metric_alarm" "frontend_scale_up_alarm" {
  alarm_name          = "frontend-high-cpu-usage"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 20
  alarm_description   = "This metric checks if CPU usage is higher than 20% in the past 2 min"
  alarm_actions       = [aws_autoscaling_policy.frontend_scale_up_policy.arn]
  actions_enabled     = true
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.frontend_asg.name
  }
}

resource "aws_cloudwatch_metric_alarm" "backend_scale_up_alarm" {
  alarm_name          = "backend-high-cpu-usage"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 20
  alarm_description   = "This metric checks if CPU usage is higher than 20% in the past 2 min"
  alarm_actions       = [aws_autoscaling_policy.backend_scale_up_policy.arn]
  actions_enabled     = true
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.backend_asg.name
  }
}

resource "aws_cloudwatch_metric_alarm" "frontend_scale_down_alarm" {
  alarm_name          = "frontend-low-cpu-usage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 10
  alarm_description   = "This metric checks if CPU usage is lower than 10% for the past 2 min"
  alarm_actions       = [aws_autoscaling_policy.frontend_scale_down_policy.arn]
  actions_enabled     = true
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.frontend_asg.name
  }
}

resource "aws_cloudwatch_metric_alarm" "backend_scale_down_alarm" {
  alarm_name          = "backend-low-cpu-usage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 10
  alarm_description   = "This metric checks if CPU usage is lower than 10% for the past 2 min"
  alarm_actions       = [aws_autoscaling_policy.backend_scale_down_policy.arn]
  actions_enabled     = true
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.backend_asg.name
  }
}

# Scale up policy
resource "aws_autoscaling_policy" "frontend_scale_up_policy" {
  name                   = "frontend_scale-up-policy"
  policy_type            = "SimpleScaling"
  autoscaling_group_name = aws_autoscaling_group.frontend_asg.name
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
}

resource "aws_autoscaling_policy" "backend_scale_up_policy" {
  name                   = "backend_scale-up-policy"
  policy_type            = "SimpleScaling"
  autoscaling_group_name = aws_autoscaling_group.backend_asg.name
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
}

# Scale down policy
resource "aws_autoscaling_policy" "frontend_scale_down_policy" {
  name                   = "frontend_scale-down-policy"
  policy_type            = "SimpleScaling"
  autoscaling_group_name = aws_autoscaling_group.frontend_asg.name
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
}

resource "aws_autoscaling_policy" "backend_scale_down_policy" {
  name                   = "backend_scale-down-policy"
  policy_type            = "SimpleScaling"
  autoscaling_group_name = aws_autoscaling_group.backend_asg.name
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2_profile"
  role = aws_iam_role.EC2-EventRise.name
}

# Create access key pair.

resource "aws_key_pair" "ec2keypair" {
  key_name   = "ec2.pub"
  public_key = file("~/.ssh/ec2.pub")
}

data "aws_route53_zone" "selected" {
  name = var.domain
}

data "aws_route53_zone" "sub_select" {
  name = "api.eventrise.me"
}

# Create a new A record that points to the Load balancer.

resource "aws_route53_record" "new_record" {
  zone_id = data.aws_route53_zone.selected.zone_id
  name    = data.aws_route53_zone.selected.name
  type    = "A"
  alias {
    name                   = aws_lb.frontend-lb.dns_name
    zone_id                = aws_lb.frontend-lb.zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "sub_new_record" {
  zone_id = data.aws_route53_zone.sub_select.zone_id
  name    = data.aws_route53_zone.sub_select.name
  type    = "A"
  alias {
    name                   = aws_lb.backend-lb.dns_name
    zone_id                = aws_lb.backend-lb.zone_id
    evaluate_target_health = true
  }
}