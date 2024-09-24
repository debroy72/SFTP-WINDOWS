#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <iostream>
#include <fstream>

#ifdef _WIN32
    #include <fcntl.h>
#else
    #include <sys/stat.h>
    #include <fcntl.h>
#endif

int sftp_upload_file(ssh_session session, const char* local_file, const char* remote_file) {
    sftp_session sftp = sftp_new(session);
    if (sftp == NULL) {
        std::cerr << "Error creating SFTP session: " << ssh_get_error(session) << std::endl;
        return SSH_ERROR;
    }

    if (sftp_init(sftp) != SSH_OK) {
        std::cerr << "Error initializing SFTP session: " << sftp_get_error(sftp) << std::endl;
        sftp_free(sftp);
        return SSH_ERROR;
    }

    sftp_file file = sftp_open(sftp, remote_file, O_WRONLY | O_CREAT | O_TRUNC, 0);
    if (file == NULL) {
        std::cerr << "Error opening remote file: " << ssh_get_error(session) << std::endl;
        sftp_free(sftp);
        return SSH_ERROR;
    }

    std::ifstream ifs(local_file, std::ios::binary);
    if (!ifs) {
        std::cerr << "Error opening local file: " << local_file << std::endl;
        sftp_close(file);
        sftp_free(sftp);
        return SSH_ERROR;
    }

    char buffer[4096];
    while (ifs.read(buffer, sizeof(buffer)) || ifs.gcount()) {
        if (sftp_write(file, buffer, static_cast<size_t>(ifs.gcount())) < 0) {
            std::cerr << "Error writing to remote file: " << ssh_get_error(session) << std::endl;
            ifs.close();
            sftp_close(file);
            sftp_free(sftp);
            return SSH_ERROR;
        }
    }

    ifs.close();
    sftp_close(file);
    sftp_free(sftp);
    return SSH_OK;
}

int main() {
    const char* hostname = "example.com"; // Replace with your hostname
    const char* username = "user";   
    // Replace with your username
    const char* private_key_path = "C:\\Users\\HP\\.ssh\\my_private_key"; // Update path if needed
    const char* local_file = "local_file.txt";  // Update with your local file
    const char* remote_file = "/remote/path/remote_file.txt"; // Update with your remote path

    ssh_session session = ssh_new();
    if (session == NULL) {
        std::cerr << "Error creating SSH session" << std::endl;
        return 1;
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, hostname);
    ssh_options_set(session, SSH_OPTIONS_USER, username);

    if (ssh_connect(session) != SSH_OK) {
        std::cerr << "Error connecting to server: " << ssh_get_error(session) << std::endl;
        ssh_free(session);
        return 1;
    }

    // Load the private key
    ssh_key private_key;
    if (ssh_pki_import_privkey_file(private_key_path, nullptr, nullptr, nullptr, &private_key) != SSH_OK) {
        std::cerr << "Error loading private key: " << ssh_get_error(session) << std::endl;
        ssh_disconnect(session);
        ssh_free(session);
        return 1;
    }

    // Authenticate using the private key
if (ssh_userauth_publickey(session, nullptr, private_key) != SSH_AUTH_SUCCESS) {
    std::cerr << "Error authenticating with public key: " << ssh_get_error(session) << std::endl;
    ssh_key_free(private_key); // Correctly free the key
    ssh_disconnect(session);
    ssh_free(session);
    return 1;
}


    ssh_key_free(private_key); // Free the key after use

    if (sftp_upload_file(session, local_file, remote_file) != SSH_OK) {
        std::cerr << "Error uploading file" << std::endl;
        ssh_disconnect(session);
        ssh_free(session);
        return 1;
    }

    std::cout << "File uploaded successfully!" << std::endl;

    ssh_disconnect(session);
    ssh_free(session);

    return 0;
}
