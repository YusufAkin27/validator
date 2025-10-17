/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.decard.exampleSrc.samav2;


/**
 *
 * @author duma
 */
public interface ISamService {
    
    /**
     * Genera los bytes cifrados que se enviaran a la tarjeta MifarePLUS a
     * trav�s del comando Auth.
     *
     * @param firtsAuth
     * @param level
     * @param key_no
     * @param key_ver
     * @param data
     * @param data_div
     * @return
     * @throws Exception
     */
    public byte[] samAV2_authMFP_f1(boolean firtsAuth, int level, int key_no, int key_ver, byte[] data, byte[] data_div) throws Exception;
    
    public boolean samAV2_authMFP_f2(byte[] data) throws Exception;
    
    public byte[] samAV2_plainReadMFP(int bloq, int len) throws Exception;
    
    //<editor-fold defaultstate="collapsed" desc="SamAV2-MifarePLUS">
    /**
     * Genera los bytes cifrados que se enviaran a la tarjeta MifarePLUS a
     * trav�s del comando Read. Este metodo solo lee en modo plano, para
     * habilitar la lectura en modo cifrado ser� necesario modificar el metodo
     *
     * @param bloq posici�n en la trajeta del bloque de datos a leer
     * @param len longitud de bloques a leer
     * @return
     * @throws Exception
     */
    public byte[] samAV2_combinedReadMFP(byte cmd[], byte[] dataResp) throws Exception;
    
    /**
     * Genera los bytes cifrados que se enviaran a la tarjeta MifarePLUS a
     * trav�s del comando Write (write, decrement, increment, transfer).
     *
     * @param data
     * @return
     * @throws Exception
     */
    public byte[] samAV2_combinedWriteMFP(byte[] data) throws Exception;
    
    public byte[] samAV2_plainWriteMFP(int bloq, byte[] data) throws Exception;
    
    public byte[] samAV2_decrTransMFP(int bloq, int value) throws Exception;

    public byte[] samAV2_llaveDiv(byte keyIdentifier, byte[] numeroUnicoTarjetaByteArray) throws Exception;

    boolean disconnectSAM() ;

    public byte[] connectSAM() ;

    public boolean samAV2_authHost(byte[] key, int noKey) ;

}
