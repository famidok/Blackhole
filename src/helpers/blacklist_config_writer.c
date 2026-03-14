#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#define MAX_FIELD 64

typedef struct {
    const char *name;
    uint8_t value;
} protocol_map_t;

static const protocol_map_t PROTOCOL_TABLE[] = {
    {"HOPOPT", 0}, {"ICMP", 1}, {"IGMP", 2}, {"GGP", 3}, {"IPv4", 4},
    {"ST", 5}, {"TCP", 6}, {"CBT", 7}, {"EGP", 8}, {"IGP", 9},
    {"UDP", 17}, {"IPv6", 41}, {"GRE", 47}, {"ESP", 50}, {"AH", 51},
    {"ICMPv6", 58}, {"IPv6-ICMP", 58}, {"SCTP", 132}, {"Ethernet", 143}
};

uint8_t get_protocol_number(const char *proto) {
    if (isdigit(proto[0])) {
        int n = atoi(proto);
        if (n >= 0 && n <= 254) return (uint8_t)n;
    }
    for (size_t i = 0; i < sizeof(PROTOCOL_TABLE)/sizeof(PROTOCOL_TABLE[0]); i++) {
        if (strcasecmp(proto, PROTOCOL_TABLE[i].name) == 0) return PROTOCOL_TABLE[i].value;
    }
    return 255;
}

int is_valid_ip(const char *ip) {
    int num, dots = 0;
    char ptr[MAX_FIELD];
    strcpy(ptr, ip);
    char *token = strtok(ptr, ".");
    if (token == NULL) return 0;
    while (token) {
        for (int i = 0; i < (int)strlen(token); i++) {
            if (!isdigit(token[i])) return 0;
        }
        num = atoi(token);
        if (num < 0 || num > 255) return 0;
        dots++;
        token = strtok(NULL, ".");
    }
    return dots == 4;
}

int get_yes_no(const char *prompt) {
    char input[10];
    while (1) {
        printf("%s (y/n): ", prompt);
        fgets(input, sizeof(input), stdin);
        char choice = tolower(input[0]);
        if (choice == 'y') return 1;
        if (choice == 'n') return 0;
        printf("Error: Use 'y' or 'n'.\n");
    }
}

int get_binary_choice(const char *prompt) {
    char input[10];
    int val;
    while (1) {
        printf("%s (0/1): ", prompt);
        fgets(input, sizeof(input), stdin);
        if (sscanf(input, "%d", &val) == 1 && (val == 0 || val == 1)) return val;
        printf("Error: Use 0 or 1.\n");
    }
}

void write_json_array(FILE *fp, const char *key, int fields, const char *field_names[]) {
    char buffer[MAX_FIELD];
    fprintf(fp, "  \"%s\": [\n", key);
    while (1) {
        fprintf(fp, "    {");
        for (int i = 0; i < fields; i++) {
            fprintf(fp, "\"%s\": ", field_names[i]);
            if (strcmp(field_names[i], "allow") == 0) {
                fprintf(fp, "%d", get_binary_choice(field_names[i]));
            } else if (strcmp(field_names[i], "protocol") == 0) {
                while (1) {
                    printf("protocol Enter a name (e.g., TCP, UDP, ICMP) or number (0-254): ");
                    fgets(buffer, sizeof(buffer), stdin);
                    buffer[strcspn(buffer, "\n")] = 0;
                    uint8_t p_num = get_protocol_number(buffer);
                    if (p_num != 255) {
                        fprintf(fp, "%u", p_num);
                        break;
                    }
                    printf("Error: Invalid protocol.\n");
                }
            } else if (strcmp(field_names[i], "destination_port") == 0) {
                int port;
                while (1) {
                    printf("destination_port (0-65535): ");
                    fgets(buffer, sizeof(buffer), stdin);
                    if (sscanf(buffer, "%d", &port) == 1 && port >= 0 && port <= 65535) {
                        fprintf(fp, "%d", port);
                        break;
                    }
                    printf("Error: Invalid port.\n");
                }
            } else {
                while (1) {
                    printf("%s: ", field_names[i]);
                    fgets(buffer, sizeof(buffer), stdin);
                    buffer[strcspn(buffer, "\n")] = 0;
                    if (strlen(buffer) > 0) {
                        if (strstr(field_names[i], "_ip") && !is_valid_ip(buffer)) {
                            printf("Error: Invalid IP.\n");
                            continue;
                        }
                        fprintf(fp, "\"%s\"", buffer);
                        break;
                    }
                }
            }
            if (i < fields - 1) fprintf(fp, ", ");
        }
        fprintf(fp, "}");
        if (!get_yes_no("Add another?")) break;
        fprintf(fp, ",\n");
    }
    fprintf(fp, "\n  ]");
}

int main(void) {
    char mode[16];
    while (1) {
        printf("Select mode (new/reset): ");
        fgets(mode, sizeof(mode), stdin);
        mode[strcspn(mode, "\n")] = 0;
        if (strcmp(mode, "new") == 0 || strcmp(mode, "reset") == 0) break;
    }
    if (strcmp(mode, "reset") == 0) {
        FILE *fp = fopen("../blacklist_config.json", "w");
        if (fp) { fprintf(fp, "{}\n"); fclose(fp); }
        return 0;
    }
    FILE *fp = fopen("../blacklist_config.json", "w");
    if (!fp) return 1;
    fprintf(fp, "{\n");
    const char *f1[] = {"source_ip", "destination_ip", "destination_port", "allow"};
    const char *f2[] = {"source_ip", "destination_ip", "allow"};
    const char *f3[] = {"destination_ip", "allow"};
    const char *f4[] = {"source_ip", "allow"};
    const char *f5[] = {"protocol", "allow"};
    const char *f6[] = {"interface_name", "allow"};
    struct { const char *k; int c; const char **f; } s[] = {
        {"three_tuple", 4, f1}, {"ip_to_ip", 3, f2}, {"any_to_ip", 2, f3},
        {"ip_to_any", 2, f4}, {"protocols", 2, f5}, {"interfaces", 2, f6}
    };
    int first = 1;
    for (int i = 0; i < 6; i++) {
        char p[128]; snprintf(p, sizeof(p), "Add entries for '%s'?", s[i].k);
        if (get_yes_no(p)) {
            if (!first) fprintf(fp, ",\n");
            write_json_array(fp, s[i].k, s[i].c, s[i].f);
            first = 0;
        }
    }
    fprintf(fp, "\n}\n");
    fclose(fp);
    return 0;
}