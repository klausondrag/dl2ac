#!/bin/bash
set -o nounset
set -o errexit
set -o pipefail
set -o xtrace

authelia_image=authelia/authelia
config_dir=extracted_config
original_file_name=configuration.yml
new_file_name=default-configuration.yml
container_id=$(sudo docker run --detach --volume "$(pwd)/${config_dir}:/config" "${authelia_image}" || true)
sudo chown -R "$(whoami):$(whoami)" "${config_dir}"
chmod 775 "${config_dir}"
chmod 644 "${config_dir}/${original_file_name}"
cp "${config_dir}/${original_file_name}" "${new_file_name}"
rm -r "${config_dir}"
sudo docker rm "${container_id}"
echo "Extracted config. Please see the file ${new_file_name}"
