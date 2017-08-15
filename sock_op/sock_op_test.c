#include "sock_op.h"

int main()
{
    struct ifi_info *head = get_ifi_info(1);
    if (head == NULL) {
        perror("Error: get none ifi_info\n");
    }

    print_ifi_info(head);
    free_ifi_info(head);

    return 0;
}