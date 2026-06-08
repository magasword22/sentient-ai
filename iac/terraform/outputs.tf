output "server_public_ip" {
  value       = aws_instance.sentient_server.public_ip
  description = "The public IP address of the deployed Sentient AI server."
}

output "streamlit_dashboard_url" {
  value       = "http://${aws_instance.sentient_server.public_ip}:8501"
  description = "The Streamlit dashboard URL for the user to connect."
}
