package com.aqua.examples.wireshark;

import java.util.ArrayList;

import systemobject.terminal.Prompt;

import com.aqua.sysobj.conn.CliConnectionImpl;
import com.aqua.sysobj.conn.Position;

public class WireSharkExampleCliConnection extends CliConnectionImpl {

	public WireSharkExampleCliConnection() {
		// TODO Auto-generated constructor stub
	}

	@Override
	public Position[] getPositions() {
		// TODO Auto-generated method stub
		return new Position[0];
	}

	@Override
	public Prompt[] getPrompts() {
		ArrayList<Prompt> prompts = new ArrayList<Prompt>();
		Prompt p = new Prompt();
		p.setPrompt("login:");
		p.setStringToSend(getUser());
		prompts.add(p);
		p = new Prompt();
		p.setPrompt("password:");
		p.setStringToSend(getPassword());
		prompts.add(p);
		p = new Prompt();
		p.setPrompt(">");
		p.setCommandEnd(true);
		prompts.add(p);
		return prompts.toArray(new Prompt[prompts.size()]);
	}

}
