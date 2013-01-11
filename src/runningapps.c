/*
 * You may redistribute this program and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#define __EXTENSIONS__

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <errno.h>

void getExecutable(const char* dirName, const char* runningapps)
{
    char link[32];
    snprintf(link, 32, "%s/path/a.out", dirName);

    char buff[PATH_MAX+1] = {0};
    ssize_t ret = readlink(link, buff, PATH_MAX);
    if (ret == PATH_MAX) {
        fprintf(stderr, "pid [%s] path too big\n", dirName);
        return;
    }
    if (ret < 1) {
        if (ENOENT != errno) {
            fprintf(stderr, "Error getting path for pid [%s], errno=[%d]\n", dirName, errno);
            if (errno == EACCES) {
                fprintf(stderr, "Is %s setuid root?\n", runningapps);
            }
        }
        return;
    }

    printf("%s %s\n", dirName, buff);
}

int main(int argc, char** argv)
{
    if (argc < 1) { return -1; }
    int uid = getuid();
	if (chdir("/proc") == -1) {
		fprintf(stderr, "chdir /proc failed\n");
		return -1;
	}

    DIR* procDir;
	if ((procDir = opendir(".")) == NULL) {
		fprintf(stderr, "cannot opendir(/proc)\n");
		return -1;
	}

    struct dirent* d;
	while ((d = readdir(procDir)) != NULL) {
        if (!atoi(d->d_name)) { continue; }
        struct stat st = { .st_dev = 0 };
        if (stat(d->d_name, &st)) { fprintf(stderr, "Failed to stat [%s]\n", d->d_name); }
        if (st.st_uid == uid || uid == 0) {
            // allow a user to examine their own processes and root can examine any process.
            getExecutable(d->d_name, argv[0]);
        }
    }

    closedir(procDir);
}
