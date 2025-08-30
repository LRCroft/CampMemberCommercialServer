using campmember_commercial_webapp_linuximg.Services.HotAgency;
using CroftTeamsWinUITemplate.Models;
using CroftTeamsWinUITemplate.Services.HotAgency;
using CroftTeamsWinUITemplate.Services.Machines;
using ProtoBuf;

namespace campmember_commercial_webapp_linuximg.Services
{
    public class CampMember_CampStore_Service
    {
        Model_CampMember_ServiceContext tempModel_CampMember_ServiceContext;
        Main_CampStore_Request_FromClient tempMain_CampStore_Request_FromClient;
        Configuration_CampStore_ClientRequestResults tempConfiguration_CampStore_ClientRequestResults;

        CampCommercialServer_Azure_Blob_CampBasement_CampMember_agency hotBlob_Agency_CampMemberBlob;

        public CampMember_CampStore_Service(Model_CampMember_ServiceContext context, Main_CampStore_Request_FromClient request)
        {
            tempModel_CampMember_ServiceContext = context;

            tempMain_CampStore_Request_FromClient = request;

            tempConfiguration_CampStore_ClientRequestResults = new Configuration_CampStore_ClientRequestResults()
            {
                Configuration_CampMember_ServiceResultx = new Configuration_CampMember_ServiceResult()
                {

                },

                Main_CampStore_DataModel_FromServerx = new Main_CampStore_DataModel_FromServer()
                {

                },

                JobID = tempMain_CampStore_Request_FromClient.JobID
            };

            hotBlob_Agency_CampMemberBlob = new CampCommercialServer_Azure_Blob_CampBasement_CampMember_agency(context);
        }






        public async Task<byte[]> RunService()
        {
            try
            {
                if (tempMain_CampStore_Request_FromClient.Main_CampStore_DataModel_FromClientx.Model_ReqSessionToBuyAGoods_Encryptedx != null)
                {
                    CryptoService hotCryptoServiceWithKeyOrderNumber1 = new CryptoService(tempModel_CampMember_ServiceContext, 1, null, null, null);

                    CampCommercialServer_Stripe_agency hotStripeAgency = new CampCommercialServer_Stripe_agency(tempModel_CampMember_ServiceContext);

                    int productToBePurchase = ByteArrayAndConversionMachine.ConvertUnicodeBytesToInt32(await hotCryptoServiceWithKeyOrderNumber1.DecryptWithCommonAgency(tempMain_CampStore_Request_FromClient.Main_CampStore_DataModel_FromClientx.Model_ReqSessionToBuyAGoods_Encryptedx.WhatToBuy));
                    int quantityToPurchase = ByteArrayAndConversionMachine.ConvertUnicodeBytesToInt32(await hotCryptoServiceWithKeyOrderNumber1.DecryptWithCommonAgency(tempMain_CampStore_Request_FromClient.Main_CampStore_DataModel_FromClientx.Model_ReqSessionToBuyAGoods_Encryptedx.Quantity));

                    Model_CampStore_ReturnedSessionToBuyAGoods_ByteArray tempModel_ReturnedSessionToBuyAGoods_ByteArray = new Model_CampStore_ReturnedSessionToBuyAGoods_ByteArray();

                    // Recurring 1.99 a month
                    if (productToBePurchase == 7)
                    {
                        string sessionString = await hotStripeAgency.CreateRecurringCheckoutSession("price_1R0n9pEgetNpsvbVUQPtm4Cd", quantityToPurchase);
                        tempModel_ReturnedSessionToBuyAGoods_ByteArray.SessionString = UnicodeReaderMachine.ConvertUnicodeStringToByteArray(sessionString);
                    }
                    // Recurring 59 USD / 3 years
                    else if (productToBePurchase == 8)
                    {
                        string sessionString = await hotStripeAgency.CreateRecurringCheckoutSession("price_1R0nAnEgetNpsvbVEOBfGFnV", quantityToPurchase);
                        tempModel_ReturnedSessionToBuyAGoods_ByteArray.SessionString = UnicodeReaderMachine.ConvertUnicodeStringToByteArray(sessionString);
                    }
                    // Lifetime 599 USD
                    else if (productToBePurchase == 999)
                    {
                        CampCommercialServer_Stripe_agency hotStripeAgency999 = new CampCommercialServer_Stripe_agency(tempModel_CampMember_ServiceContext);

                        string sessionString = await hotStripeAgency.CreateHotPaymentCheckoutSession("price_1Q87BMEgetNpsvbVPwgdx0vo", 1);
                        tempModel_ReturnedSessionToBuyAGoods_ByteArray.SessionString = UnicodeReaderMachine.ConvertUnicodeStringToByteArray(sessionString);
                    }

                    tempConfiguration_CampStore_ClientRequestResults.Main_CampStore_DataModel_FromServerx.Model_ReturnedSessionToBuyAGoods_ByteArrayx = tempModel_ReturnedSessionToBuyAGoods_ByteArray;
                    tempConfiguration_CampStore_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);
                }

                tempConfiguration_CampStore_ClientRequestResults.Configuration_CampMember_ServiceResultx.ErrorMessages += tempModel_CampMember_ServiceContext.ErrorMessage;
                await hotBlob_Agency_CampMemberBlob.AppendCampMemberServerLogAsync(tempConfiguration_CampStore_ClientRequestResults.Configuration_CampMember_ServiceResultx.ErrorMessages);

                byte[] protobufData;
                using (var stream = new MemoryStream())
                {
                    Serializer.Serialize(stream, tempConfiguration_CampStore_ClientRequestResults);
                    protobufData = stream.ToArray();
                }

                return protobufData;
            }
            catch (Exception ex)
            {
                tempModel_CampMember_ServiceContext.ErrorMessage = ex.Message;

                tempConfiguration_CampStore_ClientRequestResults.Configuration_CampMember_ServiceResultx.ErrorMessages += tempModel_CampMember_ServiceContext.ErrorMessage;
                await hotBlob_Agency_CampMemberBlob.AppendCampMemberServerLogAsync(tempConfiguration_CampStore_ClientRequestResults.Configuration_CampMember_ServiceResultx.ErrorMessages);

                byte[] protobufData;
                using (var stream = new MemoryStream())
                {
                    Serializer.Serialize(stream, tempConfiguration_CampStore_ClientRequestResults);
                    protobufData = stream.ToArray();
                }

                return protobufData;
            }






        }
    }
}