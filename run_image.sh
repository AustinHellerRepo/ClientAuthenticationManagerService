docker run --name client_authentication_manager_service -p 35124:35124 -p 39220:39220 -e "DOCKER_IP=$(ip -4 addr show docker0 | grep -Po 'inet \K[\d.]+')" --rm client_authentication_manager_service
#docker run --name client_authentication_manager_service --net=host -e "DOCKER_IP=$(ip -4 addr show docker0 | grep -Po 'inet \K[\d.]+')" --rm client_authentication_manager_service
