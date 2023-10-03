#include <iostream>
#include <cstring>
#include <cstdlib>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>

int main() {
    // Create a socket
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        std::cerr << "Error creating socket." << std::endl;
        return 1;
    }

    // Server address and port
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(12345); // Server port
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1"); // Server IP address

    // Connect to the server
    if (connect(client_socket, (struct sockaddr*)&server_address, sizeof(server_address)) == -1) {
        std::cerr << "Error connecting to server." << std::endl;
        close(client_socket);
        return 1;
    }

    // Define the task and data
    const char* task = "Task 4 ";
    int integer_array[] = {1, 2, 3, 4, 5};
    int num_elements = sizeof(integer_array) / sizeof(integer_array[0]);

    // Send the task and data to the server
    send(client_socket, task, strlen(task), 0);
    send(client_socket, integer_array, sizeof(integer_array), 0);

    // Receive the result from the server
    int sum_of_elements = 0;
    recv(client_socket, &sum_of_elements, sizeof(sum_of_elements), 0);

    // Print the received result
    std::cout << "Received from server: Sum of elements: " << sum_of_elements << std::endl;

    // Close the client socket
    close(client_socket);

    return 0;
}

