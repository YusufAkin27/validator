package com.decard.exampleSrc.desfire.ev1.model.command;

import java.io.IOException;

public interface IsoDepAdapter extends IsoDepWrapper {

    byte[] sendCommandChain(byte command, byte[] parameters, int offset, int length) throws Exception;

    byte[] sendCommandChain(byte command, byte[] parameters) throws Exception;

    byte[] sendCommand(byte command, byte[] parameters, int offset, int length, byte expect) throws Exception;

    byte[] sendCommand(byte command, byte[] parameters, byte expect) throws Exception;

    byte[] sendAdpuChain(byte[] adpu) throws Exception;

    boolean isConnected();

    public void connect() throws IOException;
    public void close() throws IOException;

}
