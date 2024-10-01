/*
 * Copyright (C) Tildeslash Ltd. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU Affero General Public License in all respects
 * for all of the code used other than OpenSSL.
 */

#include "config.h"

#include "monit.h"
#include "event.h"
#include "ProcessTable.h"
#include "TextBox.h"
#include "TextColor.h"
#include "Proc.h"


/**
 * Process releated methods which utilize the Process Table
 *
 * @author https://tildeslash.com
 * @see https://mmonit.com
 * @file
 */


/* ----------------------------------------------------------------- Private */


static inline int _findIndex(ProcessTable_T P, int pid) {
        for (int i = 0; i < P->size; i++)
                if (pid == P->table[i].pid)
                        return i;
        return -1;
}


// Scan the process table and find the oldest matching process
// whose parent doesn't match the pattern. Locking is not needed
// as this is not the Shared Process Table
static pid_t _match(ProcessTable_T P, regex_t *regex) {
        assert(P);
        pid_t pid = -1;
        int found = 0;
        for (int i = 0; i < P->size ; i++) {
                struct process_t process = P->table[i];
                if (process.pid == P->self_pid)
                        continue;
                if (STR_DEF(process.cmdline)) {
                        if (regexec(regex, process.cmdline, 0, NULL, 0) == 0) {
                                if (process.ppid > 1) {
                                        int parent = _findIndex(P, process.ppid);
                                        if (parent > 0 ) {
                                                if (STR_DEF(P->table[parent].cmdline)) {
                                                        if (regexec(regex, P->table[parent].cmdline, 0, NULL, 0) == 0)
                                                                continue;
                                                }
                                        }
                                }
                                if (found) {
                                        if (P->table[found].uptime > P->table[i].uptime)
                                                continue;
                                }
                                found = i;
                                pid = P->table[i].pid;
                        }
                }
        }
        return pid;
}


/* ------------------------------------------------------------------ Public */


void Proc_match(char *pattern) {
        regex_t *regex_comp;
        int reg_return;
        NEW(regex_comp);
        if ((reg_return = regcomp(regex_comp, pattern, REG_NOSUB|REG_EXTENDED))) {
                char errbuf[STRLEN];
                regerror(reg_return, regex_comp, errbuf, STRLEN);
                regfree(regex_comp);
                FREE(regex_comp);
                printf("Regex %s parsing error: %s\n", pattern, errbuf);
                exit(1);
        }
        ProcessTable_T P = ProcessTable_new();
        if (P) {
                int count = 0;
                printf("List of processes matching pattern \"%s\":\n", pattern);
                StringBuffer_T output = StringBuffer_create(256);
                TextBox_T t = TextBox_new(output, 4, (TextBoxColumn_T []){
                        {.name = "",        .width = 1,  .wrap = false, .align = TextBoxAlign_Left},
                        {.name = "PID",     .width = 8,  .wrap = false, .align = TextBoxAlign_Right},
                        {.name = "PPID",    .width = 8,  .wrap = false, .align = TextBoxAlign_Right},
                        {.name = "Command", .width = 50, .wrap = true,  .align = TextBoxAlign_Left}
                }, true);
                // Select the process matching the pattern
                int pid = _match(P, regex_comp);
                // Print all matching processes and highlight the one which is selected
                for (int i = 0; i < P->size; i++) {
                        if (STR_DEF(P->table[i].cmdline) && P->table[i].pid != P->self_pid) {
                                if (! regexec(regex_comp, P->table[i].cmdline, 0, NULL, 0)) {
                                        if (pid == P->table[i].pid) {
                                                TextBox_setColumn(t, 1, COLOR_BOLD "*" COLOR_RESET);
                                                TextBox_setColumn(t, 2, COLOR_BOLD "%d" COLOR_RESET, P->table[i].pid);
                                                TextBox_setColumn(t, 3, COLOR_BOLD "%d" COLOR_RESET, P->table[i].ppid);
                                                TextBox_setColumn(t, 4, COLOR_BOLD "%s" COLOR_RESET, P->table[i].cmdline);
                                        } else {
                                                TextBox_setColumn(t, 2, "%d", P->table[i].pid);
                                                TextBox_setColumn(t, 3, "%d", P->table[i].ppid);
                                                TextBox_setColumn(t, 4, "%s", P->table[i].cmdline);
                                        }
                                        TextBox_printRow(t);
                                        count++;
                                }
                        }
                }
                TextBox_free(&t);
                ProcessTable_free(&P);
                if (Run.flags & Run_Batch || ! TextColor_support())
                        TextColor_strip(TextBox_strip((char *)StringBuffer_toString(output)));
                printf("%s", StringBuffer_toString(output));
                StringBuffer_free(&output);
                printf("Total matches: %d\n", count);
                if (count > 1)
                        printf("\n"
                               "WARNING:\n"
                               "Multiple processes match the pattern. Monit will select the process with the\n"
                               "highest uptime, the one highlighted.\n");
        }
        regfree(regex_comp);
        FREE(regex_comp);
}
