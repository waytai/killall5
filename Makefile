# You may redistribute this program and/or modify it under the terms of
# the GNU General Public License as published by the Free Software Foundation,
# either version 3 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
all:
	gcc -m64 -std=c99 -o runningapps src/runningapps.c
	gcc -m64 -std=c99 -o killall5 src/killall5.c

install:
	[ "`whoami`" != "root" ] && echo "must be run as root" && exit 1 || true;
	cp killall5 /sbin/killall5
	ln -s /sbin/killall5 /bin/pidof
	cp runningapps /bin/runningapps
	chown root /bin/runningapps
	chmod 4755 /bin/runningapps
	echo Success

uninstall:
	rm -f /bin/runningapps /bin/pidof /sbin/killall5
