#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ishell.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "threads/loader.h"
#include "threads/pte.h"
#include "threads/thread.h"

#define MAX_COMMAND_NAME_LEN 8;

int is_shell_command(char *_input_buffer, char *_cmd_name, int size, int _input_buffer_end);

void ishell(void)
{
    printf("Welcome to the Interactive Shell!\n:]\n");

    char _input_buffer[256];   // buffer to keep line of input
    int _input_buffer_end = 0; // pointer to current end of line
    int _end_usr_input = 0;    // to exit

    while (1)
    {
        if (_end_usr_input)
        {
            break;
        }

        int _input_buffer_end = 0;
        printf("pintos>");

        // take line of input character by character.
        while (1)
        {
            _input_buffer[_input_buffer_end] = (char)input_getc();

            // end of line.
            if (_input_buffer[_input_buffer_end] == '\r')
            {
                printf("\n");
                break;
            }
            // backspace should remove the last printed character from the display and move the pointer
            // back by one
            else if (_input_buffer[_input_buffer_end] == '\b')
            {
                if (_input_buffer_end > 0)
                {
                    printf("\b \b");
                    _input_buffer_end -= 1;
                }
                continue;
            }

            // print each character so that the input is visible
            printf("%c", _input_buffer[_input_buffer_end]);
            _input_buffer_end += 1;
        }

        // shell commands
        // do nothing if nothing is typed.
        if (_input_buffer_end == 0)
        {
            continue;
        }

        if (is_shell_command(_input_buffer, "ram", 3, _input_buffer_end))
        {
            printf("Total RAM is %d kB \n", init_ram_pages * PGSIZE / 1024);
        }
        else if (is_shell_command(_input_buffer, "time", 4, _input_buffer_end))
        {
            long int curr_time = rtc_get_time();
            printf("%d \n", curr_time);
        }
        else if (is_shell_command(_input_buffer, "exit", 4, _input_buffer_end))
        {
            _end_usr_input = 1;
        }
        else if (is_shell_command(_input_buffer, "whoami", 6, _input_buffer_end))
        {
            printf("I am Batman\n");
        }
        else if (is_shell_command(_input_buffer, "thread", 6, _input_buffer_end))
        {
            thread_print_stats();
        }
        else if (is_shell_command(_input_buffer, "shutdown", 8, _input_buffer_end))
        {
            _end_usr_input = 1;
            shutdown_configure(SHUTDOWN_POWER_OFF);
        }
        else if (is_shell_command(_input_buffer, "priority", 8, _input_buffer_end))
        {
            int _thread_priority = thread_get_priority();
            printf("thread priority is %d \n", _thread_priority);
        }
        else
        {
            printf("command not found\n");
        }
    }
}

int is_shell_command(char *_input_buffer, char *_cmd_name, int size, int _input_buffer_end)
{
    if (size != _input_buffer_end)
    {
        return 0;
    }
    for (int i = 0; i < _input_buffer_end; i++)
    {
        if (_input_buffer[i] != _cmd_name[i])
        {
            return 0;
        }
    }
    return 1;
}