# expect: TG-GCP-FW-001, TG-GCP-GCS-001
resource "google_compute_firewall" "ssh" {
  name          = "allow-ssh"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
resource "google_storage_bucket_iam_member" "public" {
  bucket = "b"
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
