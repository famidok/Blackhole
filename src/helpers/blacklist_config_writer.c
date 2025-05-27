#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ENTRIES 100
#define MAX_FIELD 64

void write_json_array(FILE *fp, const char *key, int fields, const char *field_names[]) {
    char buffer[fields][MAX_FIELD];

    fprintf(fp, "  \"%s\": [\n", key);

    while (1) {
        for (int i = 0; i < fields; i++) {
            printf("%s: ", field_names[i]);
            fgets(buffer[i], sizeof(buffer[i]), stdin);
            buffer[i][strcspn(buffer[i], "\n")] = 0; // remove newline
        }

        fprintf(fp, "    {");
        for (int i = 0; i < fields; i++) {
            int is_numeric = strcmp(field_names[i], "destination_port") == 0 || strcmp(field_names[i], "allow") == 0;
            fprintf(fp, "\"%s\": ", field_names[i]);
            if (is_numeric)
                fprintf(fp, "%s", buffer[i]);
            else
                fprintf(fp, "\"%s\"", buffer[i]);

            if (i < fields - 1)
                fprintf(fp, ", ");
        }
        fprintf(fp, "}");

        char more[4];
        printf("Add another to '%s'? (y/n): ", key);
        fgets(more, sizeof(more), stdin);
        if (more[0] != 'y' && more[0] != 'Y') break;

        fprintf(fp, ",\n");
    }

    fprintf(fp, "\n  ]");
}

int main(void) {
    char mode[8];
    printf("Do you want to create a new config or reset the existing one? (new/reset): ");
    fgets(mode, sizeof(mode), stdin);
    mode[strcspn(mode, "\n")] = 0;

    if (strcmp(mode, "reset") == 0) {
        // Check if file exists before resetting
        FILE *check = fopen("../blacklist_config.json", "r");
        if (!check) {
            printf("File not found. Cannot reset.\n");
            return 1;
        }
        fclose(check);

        FILE *fp = fopen("../blacklist_config.json", "w");
        if (!fp) {
            perror("fopen");
            return 1;
        }
        fprintf(fp, "{}\n");
        fclose(fp);
        printf("File reset: ../blacklist_config.json\n");
        return 0;
    }

    FILE *fp = fopen("../blacklist_config.json", "w");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    fprintf(fp, "{\n");

    const char *three_tuple_fields[] = {"source_ip", "destination_ip", "destination_port", "allow"};
    const char *ip_to_ip_fields[] = {"source_ip", "destination_ip", "allow"};
    const char *any_to_ip_fields[] = {"destination_ip", "allow"};
    const char *ip_to_any_fields[] = {"source_ip", "allow"};
    const char *interface_fields[] = {"interface_name", "allow"};

    struct {
        const char *key;
        int field_count;
        const char **fields;
    } sections[] = {
        {"three_tuple", 4, three_tuple_fields},
        {"ip_to_ip", 3, ip_to_ip_fields},
        {"any_to_ip", 2, any_to_ip_fields},
        {"ip_to_any", 2, ip_to_any_fields},
        {"interface", 2, interface_fields},
    };

    int first = 1;
    for (int i = 0; i < sizeof(sections) / sizeof(sections[0]); i++) {
        char answer[4];
        printf("Do you want to add entries for '%s'? (y/n): ", sections[i].key);
        fgets(answer, sizeof(answer), stdin);
        if (answer[0] == 'y' || answer[0] == 'Y') {
            if (!first)
                fprintf(fp, ",\n");
            write_json_array(fp, sections[i].key, sections[i].field_count, sections[i].fields);
            first = 0;
        }
    }

    fprintf(fp, "\n}\n");
    fclose(fp);

    printf("JSON config written to ../blacklist_config.json\n");
    return 0;
}
