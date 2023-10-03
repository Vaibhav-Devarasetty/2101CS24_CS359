#include <iostream>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>

// Function to handle Task 1
void task1_handler(int client_socket, const char* data) {
    std::cout << "Received message from client for Task 1: " << data << std::endl;
    const char* response = "Have a good day";
    send(client_socket, response, strlen(response), 0);
}

// Function to handle Task 2
void task2_handler(int client_socket, const char* data) {
    std::cout << "Received string from client for Task 2: " << data << std::endl;
    int vowel_count = 0;
    for (int i = 0; data[i]; i++) {
        char c = tolower(data[i]);
        if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') {
            vowel_count++;
        }
    }
    char response[256];
    snprintf(response, sizeof(response), "Number of vowels: %d", vowel_count);
    send(client_socket, response, strlen(response), 0);
}

// Function to check if a string is a palindrome
bool is_palindrome(const char* s) {
    int len = strlen(s);
    for (int i = 0; i < len / 2; i++) {
        if (s[i] != s[len - i - 1]) {
            return false;
        }
    }
    return true;
}

// Function to handle Task 3
void task3_handler(int client_socket, const char* data) {
    std::cout << "Received string from client for Task 3: " << data << std::endl;
    const char* response = is_palindrome(data) ? "String is palindrome" : "String is not palindrome";
    send(client_socket, response, strlen(response), 0);
}

// Function to handle Task 4
void task4_handler(int client_socket, const char* data, int data_length) {
    int num_elements = data_length / sizeof(int);
    int* int_array = reinterpret_cast<int*>(const_cast<char*>(data));

    int sum_of_elements = 0;
    for (int i = 0; i < num_elements; i++) {
        sum_of_elements += int_array[i];
    }

    send(client_socket, &sum_of_elements, sizeof(int), 0);
}

int main() {
    // Create a socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        std::cerr << "Error creating socket." << std::endl;
        return 1;
    }

    // Bind the socket
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(12345); // Server port
    server_address.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr*)&server_address, sizeof(server_address)) == -1) {
        std::cerr << "Error binding socket." << std::endl;
        return 1;
    }

    // Listen for incoming connections
    if (listen(server_socket, 5) == -1) {
        std::cerr << "Error listening for connections." << std::endl;
        return 1;
    }

    std::cout << "Server is listening for connections..." << std::endl;

    while (true) {
        // Accept a connection from a client
        struct sockaddr_in client_address;
        socklen_t client_address_size = sizeof(client_address);
        int client_socket = accept(server_socket, (struct sockaddr*)&client_address, &client_address_size);
        if (client_socket == -1) {
            std::cerr << "Error accepting connection." << std::endl;
            continue;
        }

        std::cout << "Accepted connection from: " << inet_ntoa(client_address.sin_addr) << ":" << ntohs(client_address.sin_port) << std::endl;

        // Receive data from the client
        char buffer[1024];
        int bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);

        if (bytes_received <= 0) {
            std::cerr << "Error receiving data from client." << std::endl;
            close(client_socket);
            continue;
        }

        // Determine the task based on received data and call the corresponding handler function
        if (strncmp(buffer, "Task 1 ", 7) == 0) {
            task1_handler(client_socket, buffer + 7);
        } else if (strncmp(buffer, "Task 2 ", 7) == 0) {
            task2_handler(client_socket, buffer + 7);
        } else if (strncmp(buffer, "Task 3 ", 7) == 0) {
            task3_handler(client_socket, buffer + 7);
        } else if (strncmp(buffer, "Task 4 ", 7) == 0) {
            task4_handler(client_socket, buffer + 7, bytes_received - 7);
        } else {
            const char* response = "Invalid task request";
            send(client_socket, response, strlen(response), 0);
        }

        // Close the client socket
        close(client_socket);
    }

    // Close the server socket
    close(server_socket);

    return 0;
}

