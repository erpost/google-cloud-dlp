- Add necessary information to 'secrets_template.py' file and rename to 'secrets.py'
- Service Account Key is not needed if running in Google Compute Engine with proper permissions:
    - DLP User
    - Service Usage Viewer

- Run 'dlp_detect_by_line.py' to see DLP work on a line-by-line basis
- Run 'dlp_detect_by_file.py' to see DLP work on the entire file
