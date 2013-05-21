package com.aqua.wireshark;

import com.aqua.sysobj.conn.CliCommand;

public class WireSharkCliCommand extends CliCommand {

	public WireSharkCliCommand(String[] command) {
		super();
		setCommands(command);
		addErrors("parse error");
		addErrors("Network is down");
		addErrors("No such file or directory");
		addErrors("command not found");
		addErrors("Invalid or unknown ");
	}

	public WireSharkCliCommand(String command) {
		this(new String[] { command });
	}

}
