# docker-wordpress-amd64
Dockerfiles for wordpress amd64

Based on official wordpress image on hub.docker.com and added a few more options.

-e HTTPS_ENABLED=[true|false] (defaults to false)
-e APACHE_HOSTNAME=...(hostname to use for the SSL certificate and apache hostname
-e APACHE_RUN_UID=...( sets the service and files within the container to set UID. Useful for linux servers where the UID inside the container is not mapped to the running user on the host)
