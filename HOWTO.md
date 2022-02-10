Installation steps
Download Zato Docker image:
- sudo docker pull registry.gitlab.com/zatosource/docker-registry/quickstart:3.2
- Create a container in which Zato components will be launched:
`sudo docker run --pull=always -it --rm -p 22022:22 -p 8183:8183 -p 11223:11223 \
  --name zato registry.gitlab.com/zatosource/docker-registry/quickstart:3.2`
- Retrieve your dynamically generated passwords. The first one is to Zato Dashboard at `http://localhost:8183, the other is for SSH connections.`
`sudo docker exec zato /bin/bash -c 'cat /opt/zato/web_admin_password \
  /opt/zato/zato_user_password'`
- That concludes the process - a Dashboard instance is running at http://localhost:8183 and you can log into it with the username of 'admin' using the password printed to the terminal above.

You can also connect via SSH to the container under which app is running. User: zato. Password: second one of the two printed on terminal above.