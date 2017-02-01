from __future__ import print_function
from __future__ import unicode_literals


from netmiko.cisco_base_connection import CiscoSSHConnection
from netmiko.cisco_base_connection import CiscoTelnetConnection


import paramiko
import telnetlib
import time
import socket
import re
import io
from os import path

from netmiko.netmiko_globals import MAX_BUFFER, BACKSPACE_CHAR
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException
from netmiko.utilities import write_bytes
from netmiko import log


class CiscoIosSSHBehindOpengear(CiscoSSHConnection):
    """Cisco IOS SSH driver."""

    def __init__(self, connect_immediately=True, ip='', host='', username='', password='', secret='', port=None,
                 device_type='', verbose=False, global_delay_factor=1, use_keys=False,
                 key_file=None, allow_agent=False, ssh_strict=False, system_host_keys=False,
                 alt_host_keys=False, alt_key_file='', ssh_config_file=None, timeout=8,
                 behind_console_serv=False, conn_setup_time=0):
        """
        Initialize attributes for establishing connection to target device.

        :param ip: IP address of target device. Not required if `host` is
            provided.
        :type ip: str
        :param host: Hostname of target device. Not required if `ip` is
                provided.
        :type host: str
        :param username: Username to authenticate against target device if
                required.
        :type username: str
        :param password: Password to authenticate against target device if
                required.
        :type password: str
        :param secret: The enable password if target device requires one.
        :type secret: str
        :param port: The destination port used to connect to the target
                device.
        :type port: int or None
        :param device_type: Class selection based on device type.
        :type device_type: str
        :param verbose: If `True` enables more verbose logging.
        :type verbose: bool
        :param global_delay_factor: Controls global delay factor value.
        :type global_delay_factor: int
        :param use_keys: If true, Paramiko will attempt to connect to
                target device using SSH keys.
        :type use_keys: bool
        :param key_file: Name of the SSH key file to use for Paramiko
                SSH connection authentication.
        :type key_file: str
        :param allow_agent: Set to True to enable connect to the SSH agent
        :type allow_agent: bool
        :param ssh_strict: If `True` Paramiko will automatically reject
                unknown hostname and keys. If 'False' Paramiko will
                automatically add the hostname and new host key.
        :type ssh_strict: bool
        :param system_host_keys: If `True` Paramiko will load host keys
                from the user's local 'known hosts' file.
        :type system_host_keys: bool
        :param alt_host_keys: If `True` host keys will be loaded from
                a local host-key file.
        :type alt_host_keys: bool
        :param alt_key_file: If `alt_host_keys` is set to `True`, provide
                the filename of the local host-key file to load.
        :type alt_key_file: str
        :param ssh_config_file: File name of a OpenSSH configuration file
                to load SSH connection parameters from.
        :type ssh_config_file: str
        :param timeout: Set a timeout on blocking read/write operations.
        :type timeout: float

        """
        print('In Behind Opengear __init__')

        self.connect_immediately=connect_immediately
        self.conn_setup_time = conn_setup_time
        self.behind_console_serv = behind_console_serv

        if ip:
            self.host = ip
            self.ip = ip
        elif host:
            self.host = host
        if not ip and not host:
            raise ValueError("Either ip or host must be set")
        if port is None:
            if 'telnet' in device_type:
                self.port = 23
            else:
                self.port = 22
        else:
            self.port = int(port)
        self.username = username
        self.password = password
        self.secret = secret
        self.device_type = device_type
        self.ansi_escape_codes = False
        self.verbose = verbose
        self.timeout = timeout

        # Use the greater of global_delay_factor or delay_factor local to method
        self.global_delay_factor = global_delay_factor

        # set in set_base_prompt method
        self.base_prompt = ''


        # determine if telnet or SSH
        if '_telnet' in device_type:
            self.protocol = 'telnet'
            self.establish_connection()
            self.session_preparation()
        else:
            self.protocol = 'ssh'

            if not ssh_strict:
                self.key_policy = paramiko.AutoAddPolicy()
            else:
                self.key_policy = paramiko.RejectPolicy()

            # Options for SSH host_keys
            self.use_keys = use_keys
            self.key_file = key_file
            self.allow_agent = allow_agent
            self.system_host_keys = system_host_keys
            self.alt_host_keys = alt_host_keys
            self.alt_key_file = alt_key_file

            # For SSH proxy support
            self.ssh_config_file = ssh_config_file

            if self.connect_immediately:
                self.establish_connection()
                self.session_preparation()

                # Clear the read buffer
                time.sleep(.3 * self.global_delay_factor)
                self.clear_buffer()


            else:
                # do nothing
                pass


    def session_preparation(self):
        """Prepare the session after the connection has been established."""
        self.set_base_prompt()
        self.disable_paging()
        self.set_terminal_width(command='terminal width 511')


    def establish_connection(self, width=None, height=None):
        """
        Establish SSH connection to the network device

        Timeout will generate a NetMikoTimeoutException
        Authentication failure will generate a NetMikoAuthenticationException

        width and height are needed for Fortinet paging setting.
        """
        if self.protocol == 'telnet':
            self.remote_conn = telnetlib.Telnet(self.host, port=self.port, timeout=self.timeout)
            self.telnet_login()
        elif self.protocol == 'ssh':

            # Convert Paramiko connection parameters to a dictionary
            ssh_connect_params = self._connect_params_dict()

            # Check if using SSH 'config' file mainly for SSH proxy support
            if self.ssh_config_file:
                self._use_ssh_config(ssh_connect_params)

            # Create instance of SSHClient object
            self.remote_conn_pre = paramiko.SSHClient()

            # Load host_keys for better SSH security
            if self.system_host_keys:
                self.remote_conn_pre.load_system_host_keys()
            if self.alt_host_keys and path.isfile(self.alt_key_file):
                self.remote_conn_pre.load_host_keys(self.alt_key_file)

            # Default is to automatically add untrusted hosts (make sure appropriate for your env)
            self.remote_conn_pre.set_missing_host_key_policy(self.key_policy)

            # initiate SSH connection
            try:
                self.remote_conn_pre.connect(**ssh_connect_params)
            except socket.error:
                msg = "Connection to device timed-out: {device_type} {ip}:{port}".format(
                    device_type=self.device_type, ip=self.host, port=self.port)
                raise NetMikoTimeoutException(msg)
            except paramiko.ssh_exception.AuthenticationException as auth_err:
                msg = "Authentication failure: unable to connect {device_type} {ip}:{port}".format(
                    device_type=self.device_type, ip=self.host, port=self.port)
                msg += '\n' + str(auth_err)
                raise NetMikoAuthenticationException(msg)

            if self.verbose:
                print("SSH connection established to {0}:{1}".format(self.host, self.port))

            # Use invoke_shell to establish an 'interactive session'
            if width and height:
                self.remote_conn = self.remote_conn_pre.invoke_shell(term='vt100', width=width,
                                                                     height=height)
            else:
                self.remote_conn = self.remote_conn_pre.invoke_shell()

            self.remote_conn.settimeout(self.timeout)
            self.special_login_handler()
            if self.verbose:
                print("Interactive SSH session established")

            ### custom code added below
            # Why this is needed:
            # For some reason, the Opengear Console Server needs more time
            # To establish the connection.  There may be a better way to do this
            # but I haven't found it yet.
            if self.behind_console_serv:
                time.sleep(self.conn_setup_time)
                self.remote_conn.sendall(write_bytes('\r\n\r\n\r\n'))
                print(self.remote_conn.recv_ready())
            ### custom code added above

        # make sure you can read the channel
        i = 0
        delay_factor = self.select_delay_factor(delay_factor=0)
        main_delay = delay_factor * .1
        time.sleep(main_delay)
        while i <= 40:
            new_data = self.read_channel()
            if new_data:
                break
            else:
                self.write_channel('\n')
                main_delay = main_delay * 1.1
                if main_delay >= 8:
                    main_delay = 8
                time.sleep(main_delay)
                i += 1
        # check if data was ever present
        if new_data:
            return ""
        else:
            raise NetMikoTimeoutException("Timed out waiting for data")

    def send_command_with_debug(self, command_string, expect_string=None,
                     delay_factor=1, max_loops=500, auto_find_prompt=True,
                     strip_prompt=True, strip_command=True, debug=False):
        '''
        Send command to network device retrieve output until router_prompt or expect_string

        By default this method will keep waiting to receive data until the network device prompt is
        detected. The current network device prompt will be determined automatically.

        command_string = command to execute
        expect_string = pattern to search for uses re.search (use raw strings)
        delay_factor = decrease the initial delay before we start looking for data
        max_loops = number of iterations before we give up and raise an exception
        strip_prompt = strip the trailing prompt from the output
        strip_command = strip the leading command from the output
        '''
        # debug = False # comment this out to avoid hard coding it
        delay_factor = self.select_delay_factor(delay_factor)

        # Find the current router prompt
        if expect_string is None:
            if auto_find_prompt:
                try:
                    prompt = self.find_prompt(delay_factor=delay_factor)
                except ValueError:
                    prompt = self.base_prompt
                if debug:
                    print("Found prompt: {}".format(prompt))
            else:
                prompt = self.base_prompt
            search_pattern = re.escape(prompt.strip())
        else:
            search_pattern = expect_string

        command_string = self.normalize_cmd(command_string)
        if debug:
            print("Command is: {0}".format(command_string))
            print("Search to stop receiving data is: '{0}'".format(search_pattern))

        time.sleep(delay_factor * .2)
        self.clear_buffer()
        self.write_channel(command_string)

        # Initial delay after sending command
        i = 1
        # Keep reading data until search_pattern is found (or max_loops)
        output = ''
        while i <= max_loops:
            new_data = self.read_channel()
            if debug:
                print('Loop: {} Output: "{}"'.format(i, output.encode('utf-8')))
                # Makes it easier to debug issues with not finding the output you
                # Are looking for. Converting to bytes keeps everything on one
                # line and shows hidden characters.
            if new_data:
                output += new_data
                # if debug: # comment out
                #     print("{}:{}".format(i, output))
                try:
                    lines = output.split("\n")
                    first_line = lines[0]
                    # First line is the echo line containing the command. In certain situations
                    # it gets repainted and needs filtered
                    if BACKSPACE_CHAR in first_line:
                        pattern = search_pattern + r'.*$'
                        first_line = re.sub(pattern, repl='', string=first_line)
                        lines[0] = first_line
                        output = "\n".join(lines)
                except IndexError:
                    pass
                if re.search(search_pattern, output):
                    break
            else:
                time.sleep(delay_factor * .2)
            i += 1
        else:  # nobreak
            raise IOError("Search pattern never detected in send_command_expect: {0}".format(
                search_pattern))

        output = self._sanitize_output(output, strip_command=strip_command,
                                       command_string=command_string, strip_prompt=strip_prompt)
        return output

