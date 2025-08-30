using Azure.Data.Tables;
using campmember_commercial_webapp_linuximg.Models;
using campmember_commercial_webapp_linuximg.Services;
using campmember_commercial_webapp_linuximg.Services.BackgroundServices;
using CroftTeamsWinUITemplate.Models;
using CroftTeamsWinUITemplate.Services.HotAgency;
using CroftTeamsWinUITemplate.Services.Machines;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Scripting.Utils;
using MimeKit.Cryptography;
using Oracle.ManagedDataAccess.Client;
using Org.BouncyCastle.Utilities.Encoders;
using Polly;
using ProtoBuf;
using Stripe.Treasury;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using static IronPython.Runtime.Profiler;


namespace campmember_commercial_webapp_linuximg
{
    public class Program
    {
        public static CampCommercialServer_SignalR_agency? CampConnectServiceInstance { get; set; }

        public static bool isExternalWorkerDeviceWaitingForAJob { get; set; }


        public static CampCommercialServer_RedHat_Keycloak_ConfidentialServiceAccount_agency hotRedHat_Keycloak_ConfidentialServiceAccount_agency;








        public static ConcurrentDictionary<string, ConcurrentBag<Model_CampPasswordManagerEnterprise_CachePublicKey>> ListModel_CampPasswordManagerEnterprise_CachePublicKey = new ConcurrentDictionary<string, ConcurrentBag<Model_CampPasswordManagerEnterprise_CachePublicKey>>();

        public static ConcurrentDictionary<string, Model_CampPasswordManagerEnterprise_CachePassword> ListModel_CampPasswordManagerEnterprise_CachePassword = new ConcurrentDictionary<string, Model_CampPasswordManagerEnterprise_CachePassword>();














        public static List<Model_PowerJob_PowerContributorJob> CDTRequestList;

         
        public static string PublicKey;
        public static string PrivateKey;
        public static DateTime RuntimeKeyUpdateDateTime;


















        public static void Main(string[] args)
        {
            hotRedHat_Keycloak_ConfidentialServiceAccount_agency = new CampCommercialServer_RedHat_Keycloak_ConfidentialServiceAccount_agency();


            CDTRequestList = new List<Model_PowerJob_PowerContributorJob>();
            isExternalWorkerDeviceWaitingForAJob = false;

            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddRazorPages();
            builder.Services.AddControllersWithViews();
            builder.Services.AddDistributedMemoryCache();

            builder.Services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromMinutes(30);
                options.Cookie.HttpOnly = true;
                options.Cookie.IsEssential = true;
            });





            builder.Services.AddHostedService<CCMCWA_RuntimeRSA4096DailyRotation>();







            // === LOGGING WITH TIMESTAMP ===
            builder.Logging.ClearProviders();
            builder.Logging.AddConsole(options =>
            {
                options.TimestampFormat = "[yyyy-MM-dd HH:mm:ss.fff] ";
                options.IncludeScopes = true;
            });
            builder.Logging.SetMinimumLevel(LogLevel.Trace);

            // === FORWARDED HEADERS ===
            builder.Services.Configure<ForwardedHeadersOptions>(options =>
            {
                options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
                options.KnownNetworks.Clear();
                options.KnownProxies.Clear();
            });

            // === KESTREL HTTPS ===
            builder.WebHost.ConfigureKestrel(options =>
            {
                options.ListenAnyIP(443, listenOptions =>
                {
                    listenOptions.Protocols = HttpProtocols.Http1AndHttp2AndHttp3;
                    var certPath = Path.Combine(AppContext.BaseDirectory, "Certificate", "wildcardcpm.pfx");
                    if (File.Exists(certPath))
                        listenOptions.UseHttps(certPath, "CampMember");
                    else
                        listenOptions.UseHttps();
                });
            });

            // === CORS ===
            builder.Services.AddCors(options =>
            {
                options.AddDefaultPolicy(policy =>
                {
                    policy.AllowAnyHeader()
                          .AllowAnyMethod()
                          .AllowCredentials()
                          .SetIsOriginAllowed(origin => true);
                });
            });

            // === SIGNALR ===
            builder.Services.AddSignalR(options =>
            {
                options.MaximumReceiveMessageSize = 1024 * 1024 * 1024;
            });
            builder.Services.AddSingleton<CampCommercialServer_SignalR_agency>();

            builder.Services.AddHttpContextAccessor();










            var app = builder.Build();

            CampConnectServiceInstance = app.Services.GetRequiredService<CampCommercialServer_SignalR_agency>();

            app.UseSession();
            app.UseForwardedHeaders();

            if (app.Environment.IsDevelopment())
                app.UseDeveloperExceptionPage();
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseRouting();

            // Note: No UseAuthentication or UseAuthorization middleware

            app.UseCors();

            app.MapRazorPages();
            app.MapControllers();
            app.MapHub<ChatHub>("/CampSignal");

            // === API ENDPOINTS ===
            app.MapGet("/api/runtimekey/public", () =>
            {
                if (string.IsNullOrEmpty(Program.PublicKey))
                    return Results.NotFound("RSA key not generated yet.");
                return Results.Text(Program.PublicKey);
            });

            // === registercampmemberuser, email verification, forgotpassword endpoints ===
            app.MapPost("/api/registercampmemberuser", async (HttpRequest request) =>
            {
                try
                {
                    var tempModel_CampMember_ServiceContext = new Model_CampMember_ServiceContext();
                    using var ms = new MemoryStream();
                    await request.Body.CopyToAsync(ms);
                    var receivedData = ms.ToArray();

                    var registrationModel = Serializer.Deserialize<Model_CampMember_ProgramIdentification>(
                        new MemoryStream(receivedData));

                    CryptoService hotCryptoService = new CryptoService(
                        tempModel_CampMember_ServiceContext,
                        null, null, null, Convert.FromBase64String(Program.PrivateKey));

                    Dictionary<string, string> decryptedFields = new Dictionary<string, string>();
                    List<Task> decryptTasks = new List<Task>();

                    void AddDecryptionTask(string key, byte[]? data)
                    {
                        if (data != null)
                        {
                            decryptTasks.Add(Task.Run(async () =>
                            {
                                var decryptedBytes = await hotCryptoService.DecryptWithRuntimeAgency(data);
                                decryptedFields[key] = UnicodeReaderMachine.ByteArrayToUnicodeAsync(decryptedBytes) ?? string.Empty;
                            }));
                        }
                        else
                            decryptedFields[key] = string.Empty;
                    }

                    var reg = registrationModel.Model_CampMember_Registerationx;
                    AddDecryptionTask("PreferredUsername", reg.PreferredUsername);
                    AddDecryptionTask("Email", reg.Email);
                    AddDecryptionTask("GivenName", reg.GivenName);
                    AddDecryptionTask("LastName", reg.LastName);
                    AddDecryptionTask("Password", reg.Password);

                    await Task.WhenAll(decryptTasks);

                    string? preferredUsername = decryptedFields.GetValueOrDefault("PreferredUsername");
                    string? email = decryptedFields.GetValueOrDefault("Email");
                    string? givenName = decryptedFields.GetValueOrDefault("GivenName");
                    string? lastName = decryptedFields.GetValueOrDefault("LastName");
                    string? password = decryptedFields.GetValueOrDefault("Password");

                    if (string.IsNullOrEmpty(preferredUsername) || string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
                        return Results.Problem("Required registration fields are missing", statusCode: 500);

                    (int code, string? registercampmemberuserLogs) = await hotRedHat_Keycloak_ConfidentialServiceAccount_agency
                        .CreateCampMemberUserAsync(preferredUsername, email, givenName, lastName, password);

                    if (code == 0)
                    {
                        try
                        {
                            registercampmemberuserLogs += await hotRedHat_Keycloak_ConfidentialServiceAccount_agency
                                .ManuallySendEmailVerification(email);
                            return Results.Ok(new { success = true, email = registercampmemberuserLogs });
                        }
                        catch (Exception ex)
                        {
                            registercampmemberuserLogs += ex.Message;
                            return Results.Problem(registercampmemberuserLogs ?? $"Send email verification error : {ex.Message}", statusCode: 500);
                        }
                    }
                    else
                        return Results.Problem(registercampmemberuserLogs ?? $"Send email verification global error", statusCode: 500);
                }
                catch (Exception ex)
                {
                    return Results.Problem(ex.Message, statusCode: 500);
                }
            });

            app.MapPost("/api/emailverificationcheck", async (HttpRequest request) =>
            {
                try
                {
                    using var ms = new MemoryStream();
                    await request.Body.CopyToAsync(ms);
                    var receivedData = ms.ToArray();

                    var model = Serializer.Deserialize<Model_CampMember_ProgramIdentification>(new MemoryStream(receivedData));

                    if (model == null || string.IsNullOrEmpty(model.Model_CampMember_EmailVerificationCheckx.EmailAddress))
                        return Results.BadRequest(new { success = false, error = "Invalid request" });

                    bool isVerified = await hotRedHat_Keycloak_ConfidentialServiceAccount_agency
                        .IsEmailVerifiedAsync(model.Model_CampMember_EmailVerificationCheckx.EmailAddress);

                    return Results.Ok(new { success = true, verified = isVerified, email = model.Model_CampMember_EmailVerificationCheckx.EmailAddress });
                }
                catch (Exception ex)
                {
                    return Results.Problem($"Error checking email verification: {ex.Message}");
                }
            });

            app.MapPost("/api/forgotpassword", async (HttpRequest request) =>
            {
                try
                {
                    var tempModel_CampMember_ServiceContext = new Model_CampMember_ServiceContext();
                    using var ms = new MemoryStream();
                    await request.Body.CopyToAsync(ms);
                    var receivedData = ms.ToArray();

                    Model_CampMember_ProgramIdentification registrationModel = Serializer.Deserialize<Model_CampMember_ProgramIdentification>(new MemoryStream(receivedData));
                    string forgotpasswordLogs = "";

                    try
                    {
                        forgotpasswordLogs = await hotRedHat_Keycloak_ConfidentialServiceAccount_agency
                            .SendPasswordResetEmailAsync(registrationModel.Model_CampMember_ForgetPasswordx.Email);
                        return Results.Ok(new { success = true });
                    }
                    catch (Exception ex)
                    {
                        return Results.Problem(forgotpasswordLogs ?? $"Send email verification error : {ex.Message}", statusCode: 500);
                    }
                }
                catch (Exception ex)
                {
                    return Results.Problem(ex.Message, statusCode: 500);
                }
            });




            app.MapPost("/api/resendemailverification", async (HttpRequest request) =>
            {
                try
                {
                    using var ms = new MemoryStream();
                    await request.Body.CopyToAsync(ms);
                    var receivedData = ms.ToArray();

                    var model = Serializer.Deserialize<Model_CampMember_ProgramIdentification>(new MemoryStream(receivedData));

                    if (model == null || string.IsNullOrEmpty(model.Model_CampMember_EmailVerificationCheckx.EmailAddress))
                        return Results.BadRequest(new { success = false, error = "Invalid request" });

                    try
                    {
                        string result = await hotRedHat_Keycloak_ConfidentialServiceAccount_agency.ManuallySendEmailVerification(model.Model_CampMember_ResendEmailVerificationx.userEmail);

                        return Results.Ok(new { success = true, ResendRequest = result });
                    }
                    catch (Exception ex)
                    {
                        return Results.Problem($"{ex.Message}", statusCode: 500);
                    }

                }
                catch (Exception ex)
                {
                    return Results.Problem($"Error checking email verification: {ex.Message}");
                }
            });



            app.Run();
        }































    }








    public class ChatHub : Hub
    {













        public override async Task OnConnectedAsync()
        {
            var connectionId = Context.ConnectionId;
            HttpRequest req = Context.GetHttpContext()?.Request;

            string? token = null;
            if (req != null && req.Headers.ContainsKey("Authorization"))
            {
                var authHeader = req.Headers["Authorization"].ToString();
                if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                    token = authHeader.Substring("Bearer ".Length).Trim();
            }

            if (string.IsNullOrEmpty(token))
            {
                await Program.CampConnectServiceInstance.CampMember_SendRuntime_Denied_ClientRequestResultToSpecificConnection(connectionId, "Token has an issue");
                Context.Abort();
                return;
            }

            (bool isTokenValid, string logsResults) = await Program.hotRedHat_Keycloak_ConfidentialServiceAccount_agency.ValidateAuthTokenAsync(token);
            if (!isTokenValid)
            {
                await Program.CampConnectServiceInstance.CampMember_SendRuntime_Denied_ClientRequestResultToSpecificConnection(connectionId, $"Token has an issue");
                Context.Abort();
                return;
            }




            string internaluser_identifier = Server_UserProfileReaderMachine.GetUserID(req);
            byte[] internaluser_identifiersha256 = ByteArrayAndConversionMachine.DoComputeStringToSHA256Hash(internaluser_identifier);
            string internaluser_email = Server_UserProfileReaderMachine.GetEmail(req);
            string internaluser_identifiersha256HEX = BitConverter.ToString(internaluser_identifiersha256).Replace("-", "").ToLowerInvariant();

            Model_CampMember_AccountAgencyConsultResults tempModel_AccountAgencyConsultResults = new Model_CampMember_AccountAgencyConsultResults();

            Model_CampMember_ServiceContext tempModel_CampMemberServiceDynamicContext = new Model_CampMember_ServiceContext
            {
                user_Identifier = internaluser_identifier,
                user_IdentifierSHA256 = internaluser_identifiersha256,
                user_IdentifierSHAHEX = internaluser_identifiersha256HEX,
                user_Email = internaluser_email,
                Model_AccountAgencyConsultResultsx = tempModel_AccountAgencyConsultResults,
                HttpRequestx = req,
                SignalIRConnectionID = Context.ConnectionId
            };






            CampCommercialServer_Azure_Blob_CampBasement_CampMember_agency hotCampCommercialServer_Azure_Blob_CampBasement_CampMember_agency = new CampCommercialServer_Azure_Blob_CampBasement_CampMember_agency(tempModel_CampMemberServiceDynamicContext);

            await hotCampCommercialServer_Azure_Blob_CampBasement_CampMember_agency.CampMemberRegisterLiveUserSignalMap();

            await hotCampCommercialServer_Azure_Blob_CampBasement_CampMember_agency.OverwriteCampMemberActiveUser();





            await base.OnConnectedAsync();
        }
























        public override async Task OnDisconnectedAsync(Exception? exception)
        {
            HttpRequest? req = Context.GetHttpContext()?.Request;

            Model_CampMember_ServiceContext tempModel_CampMember_ServiceContext = new Model_CampMember_ServiceContext();

            CampCommercialServer_Azure_Blob_CampBasement_CampMember_agency hotBlob_Agency_CampMemberBlob = new CampCommercialServer_Azure_Blob_CampBasement_CampMember_agency(tempModel_CampMember_ServiceContext);



            await hotBlob_Agency_CampMemberBlob.RemoveLiveUserSignalMapByConnectionId(Context.ConnectionId);

            await hotBlob_Agency_CampMemberBlob.RemovePowerContributeUserSignalMapByConnectionId(Context.ConnectionId);




            Program.ListModel_CampPasswordManagerEnterprise_CachePublicKey.TryRemove(Context.ConnectionId, out _);

            Program.ListModel_CampPasswordManagerEnterprise_CachePassword.TryRemove(Context.ConnectionId, out _);





            await base.OnDisconnectedAsync(exception);
        }











        public async Task AutomaticCampMemberAccountRecovery_DataGram(byte[] requestData)
        {
            HttpRequest? req = Context.GetHttpContext()?.Request;

            // 1. Extract token
            string? token = null;
            if (req != null && req.Headers.ContainsKey("Authorization"))
            {
                var authHeader = req.Headers["Authorization"].ToString();
                if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                    token = authHeader.Substring("Bearer ".Length).Trim();
            }

            if (string.IsNullOrEmpty(token))
            {
                Program.CampConnectServiceInstance.CampMember_SendRuntime_Denied_ClientRequestResultToSpecificConnection(
                    Context.ConnectionId, "Token missing");
                Context.Abort();
                return;
            }

            // 2. Validate via central Keycloak service
            (bool isTokanValid, string logsResults) = await Program.hotRedHat_Keycloak_ConfidentialServiceAccount_agency.ValidateAuthTokenAsync(token);






            byte[]? annonymousData = null;

            string internaluser_identifier = Server_UserProfileReaderMachine.GetUserID(req);
            byte[] internaluser_identifiersha256 = ByteArrayAndConversionMachine.DoComputeStringToSHA256Hash(internaluser_identifier);
            string internaluser_email = Server_UserProfileReaderMachine.GetEmail(req);
            string internaluser_identifiersha256HEX = BitConverter.ToString(internaluser_identifiersha256).Replace("-", "").ToLowerInvariant();

            Model_CampMember_AccountAgencyConsultResults tempModel_AccountAgencyConsultResults = new Model_CampMember_AccountAgencyConsultResults();

            Model_CampMember_ServiceContext tempModel_CampMemberServiceDynamicContext = new Model_CampMember_ServiceContext
            {
                user_Identifier = internaluser_identifier,
                user_IdentifierSHA256 = internaluser_identifiersha256,
                user_IdentifierSHAHEX = internaluser_identifiersha256HEX,
                user_Email = internaluser_email,
                Model_AccountAgencyConsultResultsx = tempModel_AccountAgencyConsultResults,
                HttpRequestx = req,
                SignalIRConnectionID = Context.ConnectionId
            };

            Model_CampMember_ProgramIdentification RecievedRequest;
            using (var ms = new MemoryStream(requestData))
            {
                RecievedRequest = Serializer.Deserialize<Model_CampMember_ProgramIdentification>(ms);
            }


            try
            {
                if (!isTokanValid)
                {
                    Configuration_Global_CampMember_ClientRequestResults tempCampMember_Automatic_Recover_User_Account_Service = new Configuration_Global_CampMember_ClientRequestResults
                    {
                        Configuration_CampMember_ServiceResultx = new Configuration_CampMember_ServiceResult()
                        {
                            isCampMemberServiceConnectionDenied = true
                        }
                    };

                    byte[] protobufData = null;
                    using (var stream = new MemoryStream())
                    {
                        Serializer.Serialize(stream, tempCampMember_Automatic_Recover_User_Account_Service);
                        protobufData = stream.ToArray();
                    }

                    await Clients.Caller.SendAsync("CampMember_Automatic_Recovery", protobufData);
                }
                else
                {







                    CampMember_Automatic_Recover_User_Account_Service hotService = new CampMember_Automatic_Recover_User_Account_Service(tempModel_CampMemberServiceDynamicContext, RecievedRequest);

                    annonymousData = await hotService.RecoverRequest();

                    await Clients.Caller.SendAsync("CampMember_Automatic_Recovery", annonymousData);







                    var keyRequest1 = new Model_CampPasswordManagerEnterprise_Request_Nessary_Key { PublicKeyOrder = 1 };
                    var keyRequest2 = new Model_CampPasswordManagerEnterprise_Request_Nessary_Key { PublicKeyOrder = 2 };
                    var accessKeyAgency = new CampCommercialServer_AccessKey_agency(tempModel_CampMemberServiceDynamicContext, null);

                    var task1 = accessKeyAgency.GetDefaultPublicKey(keyRequest1);
                    var task2 = accessKeyAgency.GetDefaultPublicKey(keyRequest2);
                    await Task.WhenAll(task1, task2);
                    var key1 = task1.Result;
                    var key2 = task2.Result;

                    var cacheKey1 = new Model_CampMember_NecessaryKey_ByteArray
                    {
                        exponent = key1.exponent,
                        modulus = key1.modulus,
                        KeyOrder = 1,
                        UserIdentifierSHA = key1.UserIdentifierSHA
                    };
                    var cacheKey2 = new Model_CampMember_NecessaryKey_ByteArray
                    {
                        exponent = key2.exponent,
                        modulus = key2.modulus,
                        KeyOrder = 2,
                        UserIdentifierSHA = key2.UserIdentifierSHA
                    };

                    var cacheEntry = new Model_CampPasswordManagerEnterprise_CachePublicKey
                    {
                        connectionID = Context.ConnectionId,
                        listOfNecessaryKeys = new List<Model_CampMember_NecessaryKey_ByteArray> { cacheKey1, cacheKey2 }
                    };

                    var bag = Program.ListModel_CampPasswordManagerEnterprise_CachePublicKey.GetOrAdd(Context.ConnectionId, _ => new ConcurrentBag<Model_CampPasswordManagerEnterprise_CachePublicKey>());

                    bag.Add(cacheEntry);





                }
            }
            catch (Exception ex)
            {
                Configuration_Global_CampMember_ClientRequestResults tempCampMember_Automatic_Recover_User_Account_Service = new Configuration_Global_CampMember_ClientRequestResults
                {
                    Configuration_CampMember_ServiceResultx = new Configuration_CampMember_ServiceResult()
                    {

                    }
                };

                tempCampMember_Automatic_Recover_User_Account_Service.Configuration_CampMember_ServiceResultx.ErrorMessages += $"Global error : {ex.Message}";

                byte[] protobufData = null;
                using (var stream = new MemoryStream())
                {
                    Serializer.Serialize(stream, tempCampMember_Automatic_Recover_User_Account_Service);
                    protobufData = stream.ToArray();
                }

                await Clients.Caller.SendAsync("CampMember_Automatic_Recovery", protobufData);
            }
        }






        public async Task CampPasswordManagerEnterprise_Request_DataGram(byte[] reqstData)
        {
            HttpRequest? req = Context.GetHttpContext()?.Request;

            // 1. Extract token
            string? token = null;
            if (req != null && req.Headers.ContainsKey("Authorization"))
            {
                var authHeader = req.Headers["Authorization"].ToString();
                if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                    token = authHeader.Substring("Bearer ".Length).Trim();
            }

            if (string.IsNullOrEmpty(token))
            {
                Program.CampConnectServiceInstance.CampMember_SendRuntime_Denied_ClientRequestResultToSpecificConnection(
                    Context.ConnectionId, "Token missing");
                Context.Abort();
                return;
            }

            // 2. Validate via central Keycloak service
            (bool isTokanValid, string logsResults) = await Program.hotRedHat_Keycloak_ConfidentialServiceAccount_agency.ValidateAuthTokenAsync(token);

            byte[]? annonymousData = null;
            int? callIdentification = null;

            string internaluser_identifier = Server_UserProfileReaderMachine.GetUserID(req);
            byte[] internaluser_identifiersha256 = ByteArrayAndConversionMachine.DoComputeStringToSHA256Hash(internaluser_identifier);
            string internaluser_email = Server_UserProfileReaderMachine.GetEmail(req);
            string internaluser_identifiersha256HEX = BitConverter.ToString(internaluser_identifiersha256).Replace("-", "").ToLowerInvariant();

            Model_CampMember_AccountAgencyConsultResults tempModel_AccountAgencyConsultResults = new Model_CampMember_AccountAgencyConsultResults();

            Model_CampMember_ServiceContext tempModel_CampMemberServiceDynamicContext = new Model_CampMember_ServiceContext
            {
                user_Identifier = internaluser_identifier,
                user_IdentifierSHA256 = internaluser_identifiersha256,
                user_IdentifierSHAHEX = internaluser_identifiersha256HEX,
                user_Email = internaluser_email,
                Model_AccountAgencyConsultResultsx = tempModel_AccountAgencyConsultResults,
                HttpRequestx = req,
                SignalIRConnectionID = Context.ConnectionId
            };

            Main_CampPasswordManagerEnterprise_Request_FromClient RecievedRequest;
            using (var ms = new MemoryStream(reqstData))
            {
                RecievedRequest = Serializer.Deserialize<Main_CampPasswordManagerEnterprise_Request_FromClient>(ms);
            }

            try
            {
                if (!isTokanValid)
                {
                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Denied_ClientRequestResultToSpecificConnection(Context.ConnectionId, "Session expired");

                    Configuration_CampPasswordManagerEnterprise_ClientRequestResults tempConfiguration_CPMEClientRequestResults = new Configuration_CampPasswordManagerEnterprise_ClientRequestResults
                    {
                        Configuration_CampMember_ServiceResultx = new Configuration_CampMember_ServiceResult()
                        {
                            isCampMemberServiceConnectionDenied = true
                        },

                        Main_DataModel_FromServerx = new Main_CampPasswordManagerEnterprise_DataModel_FromServer(),

                        JobID = RecievedRequest.JobID
                    };

                    byte[] protobufData;
                    using (var stream = new MemoryStream())
                    {
                        Serializer.Serialize(stream, tempConfiguration_CPMEClientRequestResults);
                        protobufData = stream.ToArray();
                    }

                    await Clients.Caller.SendAsync("CampPasswordManagerEnterprise_Response", protobufData);
                }
                else
                {
                    bool isFallbackNeed = false;

                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, "Flow check");

                    if (RecievedRequest.Main_DataModel_FromClientx.Model_CPME_Request_Nessary_Keyx != null)
                    {
                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, "Nesessary key AAAA");

                        var requestedOrder = RecievedRequest.Main_DataModel_FromClientx.Model_CPME_Request_Nessary_Keyx.PublicKeyOrder;

                        // Try get the bag for this user
                        if (Program.ListModel_CampPasswordManagerEnterprise_CachePublicKey
                            .TryGetValue(Context.ConnectionId, out var bag))
                        {

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, "Nesessary key has a bag");

                            // Flatten all entries and find the requested key
                            var matchedKey = bag
                                .SelectMany(entry => entry.listOfNecessaryKeys)
                                .FirstOrDefault(k => k.KeyOrder == requestedOrder);

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, "Nesessary key has a cache");

                            if (matchedKey != null)
                            {
                                await Program.CampConnectServiceInstance.CampMember_SendRuntime_Success_ToSpecificConnection(Context.ConnectionId, "Fetch managed runtime client public key");

                                CryptoService hotCryptoService = new CryptoService(tempModel_CampMemberServiceDynamicContext, null, null, RecievedRequest.PublicKey, null);



                                var tempConfiguration_CPME_ClientRequestResults = new Configuration_CampPasswordManagerEnterprise_ClientRequestResults
                                {
                                    Configuration_CampMember_ServiceResultx = new Configuration_CampMember_ServiceResult(),
                                    Main_DataModel_FromServerx = new Main_CampPasswordManagerEnterprise_DataModel_FromServer
                                    {
                                        Model_NecessaryKeyx = await hotCryptoService.AdjustmentForSendBackToClient(matchedKey)
                                    },
                                    JobID = RecievedRequest.JobID
                                };



                                byte[] protobufData;
                                using (var stream = new MemoryStream())
                                {
                                    Serializer.Serialize(stream, tempConfiguration_CPME_ClientRequestResults);
                                    protobufData = stream.ToArray();
                                }

                                await Clients.Caller.SendAsync("CampPasswordManagerEnterprise_Response", protobufData);

                                await Program.CampConnectServiceInstance.CampMember_SendRuntime_Success_ToSpecificConnection(Context.ConnectionId, "Runtime key has been transferred");

                                isFallbackNeed = false;
                            }
                            else
                            {
                                isFallbackNeed = true;
                            }
                        }
                        else
                        {
                            isFallbackNeed = false;
                        }
                    }

                    else if (RecievedRequest.Main_DataModel_FromClientx.Model_CopyPasswordx != null)
                    {
                        var tempConfiguration_CPME_ClientRequestResults = new Configuration_CampPasswordManagerEnterprise_ClientRequestResults
                        {
                            Configuration_CampMember_ServiceResultx = new Configuration_CampMember_ServiceResult(),
                            Main_DataModel_FromServerx = new Main_CampPasswordManagerEnterprise_DataModel_FromServer(),
                            JobID = RecievedRequest.JobID
                        };

                        try
                        {
                            CryptoService hotCryptoService = new CryptoService(tempModel_CampMemberServiceDynamicContext, 2, null, RecievedRequest.PublicKey, null);

                            while (!hotCryptoService.CryptoServiceStatus)
                            {
                                await Task.Delay(50);
                            }

                            // Get the cached password for this connection
                            Model_CampPasswordManagerEnterprise_CachePassword cachedPassword = Program.ListModel_CampPasswordManagerEnterprise_CachePassword.GetValueOrDefault(Context.ConnectionId);


                            if (cachedPassword != null)
                            {
                                // Send encrypted password back to client
                                tempConfiguration_CPME_ClientRequestResults.Main_DataModel_FromServerx.Model_JustPassword_ByteArrayx = await hotCryptoService.AdjustmentForSendBackToClient(cachedPassword);

                                tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);

                                // Send response to client
                                byte[] protobufData;
                                using (var stream = new MemoryStream())
                                {
                                    Serializer.Serialize(stream, tempConfiguration_CPME_ClientRequestResults);
                                    protobufData = stream.ToArray();
                                }

                                await Clients.Caller.SendAsync("CampPasswordManagerEnterprise_Response", protobufData);

                                await Program.CampConnectServiceInstance.CampMember_SendRuntime_Success_ToSpecificConnection(Context.ConnectionId, "Returned password to user");





                                RecievedRequest.Main_DataModel_FromClientx.Model_CopyPasswordx.isCallOnlyForCaching = true;

                                isFallbackNeed = true;
                            }
                            else
                            {
                                isFallbackNeed = true;
                            }
                        }
                        catch (Exception ex)
                        {
                            isFallbackNeed = true;
                        }
                    }

                    else if (RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx != null)
                    {
                        await Program.CampConnectServiceInstance.CampMember_SendRuntime_Success_ToSpecificConnection(Context.ConnectionId, "Fetching feeds cache");

                        CampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency = new CampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency(tempModel_CampMemberServiceDynamicContext);

                        CampCommercialServer_OracleObjectStorage_agency hotCampCommercialServer_OracleObjectStorage_agency = new CampCommercialServer_OracleObjectStorage_agency(tempModel_CampMemberServiceDynamicContext);






                        Model_CampPasswordManagerEnterprise_Records? tempModel_CampPasswordManagerEnterprise_Records = await hotCampCommercialServer_OracleObjectStorage_agency.CPMERecordsDownload();

                        bool isUserHasARecords = false;

                        if(tempModel_CampPasswordManagerEnterprise_Records != null)
                        {
                            int recordsCount = tempModel_CampPasswordManagerEnterprise_Records.ListModel_SpecificRecord_ByteArray_Encrypted_And_GUIDx.Count();

                            await Program.CampConnectServiceInstance.CampMember_SendRuntime_Success_ToSpecificConnection(Context.ConnectionId, $"Records count : {recordsCount}");

                            if (recordsCount > 0)
                            {
                                isUserHasARecords = true;
                            }
                            else
                            {
                                isUserHasARecords = false;
                            }
                        }
                        else
                        {
                            isUserHasARecords = false;
                        }





                        if (isUserHasARecords)
                        {

                            await Program.CampConnectServiceInstance.CampMember_SendRuntime_Success_ToSpecificConnection(Context.ConnectionId, "User has a records");

                            CryptoService hotCryptoService = new CryptoService(tempModel_CampMemberServiceDynamicContext, null, null, RecievedRequest.PublicKey, null);


                            Configuration_CampPasswordManagerEnterprise_ClientRequestResults tempConfiguration_CPME_ClientRequestResults = new Configuration_CampPasswordManagerEnterprise_ClientRequestResults
                            {
                                Configuration_CampMember_ServiceResultx = new Configuration_CampMember_ServiceResult()
                                {

                                },

                                Main_DataModel_FromServerx = new Main_CampPasswordManagerEnterprise_DataModel_FromServer()
                                {

                                },

                                JobID = RecievedRequest.JobID
                            };






                            bool? isCacheExisted = false;


                            if (RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx.fetchingMode == 0)
                            {
                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, "Fetch 1111");

                                isCacheExisted = await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewAllCacheCheckExistence();

                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, "Fetch 2222");

                                if (isCacheExisted == true)
                                {
                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching feed mode 0 available");

                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, "Fetch 3333");

                                    List<Model_CampPasswordManagerEnterprise_LandingPage_ByteArray> tempModel_CampPasswordManagerEnterprise_LandingPage_ByteArray = await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewAllCacheDownload();

                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, "Fetch 4444");

                                    while (!hotCryptoService.CryptoServiceStatus)
                                    {
                                        await Task.Delay(50);
                                    }

                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, "Fetch 5555");

                                    tempConfiguration_CPME_ClientRequestResults.Main_DataModel_FromServerx.ListModel_CampPasswordManagerEnterprise_LandingPage_Encryptedx = await hotCryptoService.EncryptLandingPageWithPublicKeyFromClient(tempModel_CampPasswordManagerEnterprise_LandingPage_ByteArray);

                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, "Fetch 6666");

                                    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);

                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, "Cache feed returned");

                                    isFallbackNeed = false;
                                }
                                else
                                {
                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching feed mode 0 NOT available");

                                    if (RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx.isEnforcementFallbackRequired)
                                    {
                                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Feed mode 0 request fallback");

                                        isFallbackNeed = true;
                                    }
                                    else
                                    {
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.Object_ServiceStillUnderPreparingx = new Object_ServiceStillUnderPreparing();

                                        isFallbackNeed = false;
                                    }
                                }
                            }
                            else if (RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx.fetchingMode == 1)
                            {
                                isCacheExisted = await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewFavoriteCacheCheckExistence();

                                if (isCacheExisted == true)
                                {
                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching feed mode 1 available");

                                    List<Model_CampPasswordManagerEnterprise_LandingPage_ByteArray> tempModel_CampPasswordManagerEnterprise_LandingPage_ByteArray = await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewFavoriteCacheDownload();

                                    while (!hotCryptoService.CryptoServiceStatus)
                                    {
                                        await Task.Delay(50);
                                    }

                                    tempConfiguration_CPME_ClientRequestResults.Main_DataModel_FromServerx.ListModel_CampPasswordManagerEnterprise_LandingPage_Encryptedx = await hotCryptoService.EncryptLandingPageWithPublicKeyFromClient(tempModel_CampPasswordManagerEnterprise_LandingPage_ByteArray);

                                    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);

                                    isFallbackNeed = false;
                                }
                                else
                                {
                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching feed mode 1 NOT available");

                                    if (RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx.isEnforcementFallbackRequired)
                                    {
                                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Feed mode 1 request fallback");

                                        isFallbackNeed = true;
                                    }
                                    else
                                    {
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.Object_ServiceStillUnderPreparingx = new Object_ServiceStillUnderPreparing();

                                        isFallbackNeed = false;
                                    }
                                }
                            }
                            else if (RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx.fetchingMode == 2)
                            {
                                isCacheExisted = await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewRecycleCacheCheckExistence();

                                if (isCacheExisted == true)
                                {
                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching feed mode 2 available");

                                    List<Model_CampPasswordManagerEnterprise_LandingPage_ByteArray> tempModel_CampPasswordManagerEnterprise_LandingPage_ByteArray = await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewRecycleCacheDownload();

                                    while (!hotCryptoService.CryptoServiceStatus)
                                    {
                                        await Task.Delay(50);
                                    }

                                    tempConfiguration_CPME_ClientRequestResults.Main_DataModel_FromServerx.ListModel_CampPasswordManagerEnterprise_LandingPage_Encryptedx = await hotCryptoService.EncryptLandingPageWithPublicKeyFromClient(tempModel_CampPasswordManagerEnterprise_LandingPage_ByteArray);

                                    tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.ServiceSuccessResult = ByteArrayAndConversionMachine.ConvertBoolToByteArray(true);

                                    isFallbackNeed = false;
                                }
                                else
                                {
                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching feed mode 2 NOT available");

                                    if (RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx.isEnforcementFallbackRequired)
                                    {
                                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Feed mode 2 request fallback");

                                        isFallbackNeed = true;
                                    }
                                    else
                                    {
                                        tempConfiguration_CPME_ClientRequestResults.Configuration_CampMember_ServiceResultx.Object_ServiceStillUnderPreparingx = new Object_ServiceStillUnderPreparing();

                                        isFallbackNeed = false;
                                    }
                                }
                            }






                            byte[] protobufData;
                            using (var stream = new MemoryStream())
                            {
                                Serializer.Serialize(stream, tempConfiguration_CPME_ClientRequestResults);
                                protobufData = stream.ToArray();
                            }

                            await Clients.Caller.SendAsync("CampPasswordManagerEnterprise_Response", protobufData);

                            await Program.CampConnectServiceInstance.CampMember_SendRuntime_Success_ToSpecificConnection(Context.ConnectionId, "Returned result to user");

                        }
                        else
                        {
                            await Program.CampConnectServiceInstance.CampMember_SendRuntime_Success_ToSpecificConnection(Context.ConnectionId, "Generate empty list");

                            Configuration_CampPasswordManagerEnterprise_ClientRequestResults tempConfiguration_CPME_ClientRequestResults = new Configuration_CampPasswordManagerEnterprise_ClientRequestResults
                            {
                                Configuration_CampMember_ServiceResultx = new Configuration_CampMember_ServiceResult()
                                {

                                },

                                Main_DataModel_FromServerx = new Main_CampPasswordManagerEnterprise_DataModel_FromServer()
                                {

                                },

                                JobID = RecievedRequest.JobID
                            };

                            tempConfiguration_CPME_ClientRequestResults.Main_DataModel_FromServerx.ListModel_CampPasswordManagerEnterprise_LandingPage_Encryptedx = new List<Model_CampPasswordManagerEnterprise_LandingPage_Encrypted>();


                            byte[] protobufData;
                            using (var stream = new MemoryStream())
                            {
                                Serializer.Serialize(stream, tempConfiguration_CPME_ClientRequestResults);
                                protobufData = stream.ToArray();
                            }

                            await Clients.Caller.SendAsync("CampPasswordManagerEnterprise_Response", protobufData);

                            await Program.CampConnectServiceInstance.CampMember_SendRuntime_Success_ToSpecificConnection(Context.ConnectionId, "Returned empty list cache");

                            isFallbackNeed = false;
                        }

                        




                    }

                    else
                    {
                        isFallbackNeed = true;
                    }





                    Main_Cache_CampPasswordManagerEnterprise? tempMain_Cache_CampPasswordManagerEnterprise = null;



                    if (isFallbackNeed)
                    {
                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, "Fallback flow");

                        Camp_Password_Manager_Enterprise_Service hotCPMEService = new Camp_Password_Manager_Enterprise_Service(tempModel_CampMemberServiceDynamicContext, RecievedRequest);

                        (byte[] annonymousDataFallbackGlobal, tempMain_Cache_CampPasswordManagerEnterprise) = await hotCPMEService.RunService();

                        await Clients.Caller.SendAsync("CampPasswordManagerEnterprise_Response", annonymousDataFallbackGlobal);

                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Success_ToSpecificConnection(Context.ConnectionId, "Returned response");
                    }







                    await Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, $"Run cache service");



                    if (RecievedRequest.Main_DataModel_FromClientx.Model_TNCPVCSignedProtectedSHAandMakeDeclarationx != null)
                    {
                        CampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency = new CampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency(tempModel_CampMemberServiceDynamicContext);

                        bool? isCacheStillValid = await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.CPMEUserConfigCacheCheckExistence();






                        if (isCacheStillValid == true)
                        {
                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, "Cache still valid");


                            CampPasswordManagerEnterprise_Configuration_Filtered_ByteArray tempCampMember_Configuration_Filtered_ByteArray = await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.CPMEUserConfigCacheDownload();

                            tempCampMember_Configuration_Filtered_ByteArray.TNCPVESignedFromUser = tempMain_Cache_CampPasswordManagerEnterprise.CampMember_Configuration_Filtered_ByteArrayx.TNCPVESignedFromUser;

                            await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.CPMEUserConfigCacheOverwrite(tempCampMember_Configuration_Filtered_ByteArray);

                            await Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, "Cached finished");
                        }
                        else
                        {
                            await Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, "Cache expired");


                            CryptoService hotCryptoService = new CryptoService(tempModel_CampMemberServiceDynamicContext, 1, null, RecievedRequest.PublicKey, null);

                            while (!hotCryptoService.CryptoServiceStatus)
                            {
                                await Task.Delay(50);
                            }

                            CampCommercialServer_OracleObjectStorage_agency hotCampCommercialServer_OracleObjectStorage_agency = new CampCommercialServer_OracleObjectStorage_agency(tempModel_CampMemberServiceDynamicContext);

                            Configuration_CampMember_Encrypted? tempConfiguration_CampMember_Encrypted = await hotCampCommercialServer_OracleObjectStorage_agency.CPMEUserConfigDownload();

                            CPM CPM = new CPM();

                            (CampPasswordManagerEnterprise_Configuration_Filtered_ByteArray tempCampPasswordManagerEnterprise_Configuration_Filtered_ByteArray, _) = await hotCryptoService.AdjustmentForSendBackToClient(tempConfiguration_CampMember_Encrypted, CPM);

                            // Skip assignment since data that been decrypted already updated.

                            await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.CPMEUserConfigCacheOverwrite(tempCampPasswordManagerEnterprise_Configuration_Filtered_ByteArray);

                            await Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, "Cached finished");

                        }
                    }





                    else if (RecievedRequest.Main_DataModel_FromClientx.Model_ReadSpecificRecordsx != null)
                    {
                        try
                        {
                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, "Into caching password");

                            CampCommercialServer_OracleObjectStorage_agency hotCampCommercialServer_OracleObjectStorage_agency = new CampCommercialServer_OracleObjectStorage_agency(tempModel_CampMemberServiceDynamicContext);


                            if (RecievedRequest.Main_DataModel_FromClientx.Model_ReadSpecificRecordsx.PersonalKeyTaken != null)
                            {
                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, "Personal key flow");

                                CryptoService hotCryptoService = new CryptoService(tempModel_CampMemberServiceDynamicContext, null, RecievedRequest.Main_DataModel_FromClientx.Model_ReadSpecificRecordsx.PersonalKeyTaken, null, null);

                                Task<Model_CampPasswordManagerEnterprise_Records?> downloadTask = hotCampCommercialServer_OracleObjectStorage_agency.CPMERecordsDownload();
                                Task waitHot = Task.Run(async () => { while (!hotCryptoService.CryptoServiceStatus) await Task.Delay(50); });

                                await Task.WhenAll(downloadTask, waitHot);

                                var tempModel_CPME_Records = downloadTask.Result;

                                Guid targetRecordsID = tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_RecordsID_TryDecryptResultx.RecordsID;

                                Model_CampPasswordManagerEnterprise_SpecificRecord_ByteArray_Encrypted_And_GUID matchedRecord = tempModel_CPME_Records.ListModel_SpecificRecord_ByteArray_Encrypted_And_GUIDx.FirstOrDefault(r => r.UniqueIdentifier == targetRecordsID);

                                Model_CampPasswordManagerEnterprise_JustPassword_Encrypted justPassword = new Model_CampPasswordManagerEnterprise_JustPassword_Encrypted();

                                if (matchedRecord != null)
                                {
                                    justPassword.Password = matchedRecord.EncryptedPassword;
                                }

                                Model_CampPasswordManagerEnterprise_JustPassword_ByteArray resultPassword = await hotCryptoService.AdjustmentForSendBackToClient(justPassword, false);

                                Model_CampPasswordManagerEnterprise_CachePassword tempCache = new Model_CampPasswordManagerEnterprise_CachePassword
                                {
                                    connectionID = Context.ConnectionId,
                                    password = resultPassword.Password
                                };

                                Program.ListModel_CampPasswordManagerEnterprise_CachePassword[tempCache.connectionID] = tempCache;

                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, "cache password donw.");
                            }
                            else
                            {
                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, "Into caching password common");

                                CryptoService hotCryptoService = new CryptoService(tempModel_CampMemberServiceDynamicContext, 2, null, null, null);

                                Task<Model_CampPasswordManagerEnterprise_Records?> downloadTask = hotCampCommercialServer_OracleObjectStorage_agency.CPMERecordsDownload();

                                Task waitHot = Task.Run(async () => { while (!hotCryptoService.CryptoServiceStatus) await Task.Delay(50); });

                                await Task.WhenAll(downloadTask, waitHot);

                                var tempModel_CPME_Records = downloadTask.Result;

                                Guid targetRecordsID = tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_RecordsID_TryDecryptResultx.RecordsID;

                                Model_CampPasswordManagerEnterprise_SpecificRecord_ByteArray_Encrypted_And_GUID matchedRecord = tempModel_CPME_Records.ListModel_SpecificRecord_ByteArray_Encrypted_And_GUIDx.FirstOrDefault(r => r.UniqueIdentifier == targetRecordsID);

                                Model_CampPasswordManagerEnterprise_JustPassword_Encrypted justPassword = new Model_CampPasswordManagerEnterprise_JustPassword_Encrypted();

                                if (matchedRecord != null)
                                {
                                    justPassword.Password = matchedRecord.EncryptedPassword;
                                }

                                Model_CampPasswordManagerEnterprise_JustPassword_ByteArray resultPassword = await hotCryptoService.AdjustmentForSendBackToClient(justPassword, false);

                                Model_CampPasswordManagerEnterprise_CachePassword tempCache = new Model_CampPasswordManagerEnterprise_CachePassword
                                {
                                    connectionID = Context.ConnectionId,
                                    password = resultPassword.Password
                                };

                                Program.ListModel_CampPasswordManagerEnterprise_CachePassword[tempCache.connectionID] = tempCache;

                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, "Cache password Donw");

                            }
                        }
                        catch (Exception ex)
                        {
                            tempModel_CampMemberServiceDynamicContext.ErrorMessage += $"Cache password error: {ex.Message}";
                        }
                    }

                    else if (RecievedRequest.Main_DataModel_FromClientx.Model_Update_CPMUserConfigurationsx != null)
                    {
                        CampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency = new CampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency(tempModel_CampMemberServiceDynamicContext);

                        bool? isCacheStillValid = await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.CPMEUserConfigCacheCheckExistence();

                        if (isCacheStillValid == true)
                        {
                            Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResult cacheObj = tempMain_Cache_CampPasswordManagerEnterprise?.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx;

                            try
                            {
                                CampPasswordManagerEnterprise_Configuration_Filtered_ByteArray tempCampMember_Configuration_Filtered_ByteArray = await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.CPMEUserConfigCacheDownload();

                                if (tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedForceCPMLoginRequirement != null)
                                    tempCampMember_Configuration_Filtered_ByteArray.ForceCPMLoginRequirement = tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedForceCPMLoginRequirement;
                                else if (tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedLoginCPMKeyRequirement != null)
                                    tempCampMember_Configuration_Filtered_ByteArray.LoginKeyRequirement = tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedLoginCPMKeyRequirement;
                                else if (tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedLoginPINRequirement != null)
                                    tempCampMember_Configuration_Filtered_ByteArray.LoginPINRequirement = tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedLoginPINRequirement;
                                else if (tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedMakeHotFavoritePINRequirement != null)
                                    tempCampMember_Configuration_Filtered_ByteArray.MakeHotFavoritePINRequirement = tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedMakeHotFavoritePINRequirement;
                                else if (tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedCreateNewRecordsPINRequirement != null)
                                    tempCampMember_Configuration_Filtered_ByteArray.CreateNewRecordsPINRequirement = tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedCreateNewRecordsPINRequirement;
                                else if (tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedReadRecordsPINRequirement != null)
                                    tempCampMember_Configuration_Filtered_ByteArray.ReadRecordsPINRequirement = tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedReadRecordsPINRequirement;
                                else if (tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedUpdateRecordsPINRequirement != null)
                                    tempCampMember_Configuration_Filtered_ByteArray.UpdateRecordsPINRequirement = tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedUpdateRecordsPINRequirement;
                                else if (tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedCopyPasswordRecordsPINRequirement != null)
                                    tempCampMember_Configuration_Filtered_ByteArray.CopyPasswordRecordsPINRequirement = tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedCopyPasswordRecordsPINRequirement;
                                else if (tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedMoveRecordsToBinPINRequirement != null)
                                    tempCampMember_Configuration_Filtered_ByteArray.MoveRecordsToBinPINRequirement = tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedMoveRecordsToBinPINRequirement;
                                else if (tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedRecycleBinPINRequirement != null)
                                    tempCampMember_Configuration_Filtered_ByteArray.RecycleBinPINRequirement = tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedRecycleBinPINRequirement;
                                else if (tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedRecoverRecordPINRequirement != null)
                                    tempCampMember_Configuration_Filtered_ByteArray.RecoverRecordPINRequirement = tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedRecoverRecordPINRequirement;
                                else if (tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedPermanentDeleteRecordsPINRequirement != null)
                                    tempCampMember_Configuration_Filtered_ByteArray.PermanentDeleteRecordsPINRequirement = tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedPermanentDeleteRecordsPINRequirement;
                                else if (tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedNewSessionTime != null)
                                    tempCampMember_Configuration_Filtered_ByteArray.SessionMinuteForHotLoginObject = tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.decryptedNewSessionTime;


                                tempCampMember_Configuration_Filtered_ByteArray.UpdateDate = tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_UpdateUserConfig_TryDecryptResultx.updateDateTime;


                                await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.CPMEUserConfigCacheOverwrite(tempCampMember_Configuration_Filtered_ByteArray);

                                await Program.CampConnectServiceInstance.CampMember_SendRuntime_Success_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, "Cached finished");
                            }
                            catch (Exception ex)
                            {
                                await Program.CampConnectServiceInstance.CampMember_SendRuntime_Error_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, $"Cached error {ex.Message}");
                            }
                        }
                        else
                        {
                            await Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, "Cache expired");


                            CryptoService hotCryptoService = new CryptoService(tempModel_CampMemberServiceDynamicContext, 1, null, RecievedRequest.PublicKey, null);

                            while (!hotCryptoService.CryptoServiceStatus)
                            {
                                await Task.Delay(50);
                            }

                            CampCommercialServer_OracleObjectStorage_agency hotCampCommercialServer_OracleObjectStorage_agency = new CampCommercialServer_OracleObjectStorage_agency(tempModel_CampMemberServiceDynamicContext);

                            Configuration_CampMember_Encrypted? tempConfiguration_CampMember_Encrypted = await hotCampCommercialServer_OracleObjectStorage_agency.CPMEUserConfigDownload();

                            CPM CPM = new CPM();

                            (CampPasswordManagerEnterprise_Configuration_Filtered_ByteArray tempCampMember_Configuration_Filtered_ByteArray, _) = await hotCryptoService.AdjustmentForSendBackToClient(tempConfiguration_CampMember_Encrypted, CPM);

                            await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.CPMEUserConfigCacheOverwrite(tempCampMember_Configuration_Filtered_ByteArray);

                            await Program.CampConnectServiceInstance.CampMember_SendRuntime_Success_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, "Cached finished");
                        }
                    }

                    else if (RecievedRequest.Main_DataModel_FromClientx.Model_CreateNewRecordsx != null)
                    {

                        if(tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_CreateNewRecords_TryDecryptFavoriteIndicatorx.isCacheStillConsistent)
                        {
                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, $"Cache still consistent");

                            CampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency = new CampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency(tempModel_CampMemberServiceDynamicContext);

                            if (tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_CreateNewRecords_TryDecryptFavoriteIndicatorx.isFavoriteIndicated == true)
                            {
                                var downloadAllTask = hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewAllCacheDownload();
                                var downloadFavoriteTask = hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewFavoriteCacheDownload();

                                await Task.WhenAll(downloadAllTask, downloadFavoriteTask);

                                List<Model_CampPasswordManagerEnterprise_LandingPage_ByteArray> listModel_CampPasswordManagerEnterprise_LandingPage_ByteArray0 = downloadAllTask.Result;
                                List<Model_CampPasswordManagerEnterprise_LandingPage_ByteArray> listModel_CampPasswordManagerEnterprise_LandingPage_ByteArray1 = downloadFavoriteTask.Result;

                                listModel_CampPasswordManagerEnterprise_LandingPage_ByteArray0.Add(tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_CreateNewRecords_TryDecryptFavoriteIndicatorx.tempNewCacheItem);
                                listModel_CampPasswordManagerEnterprise_LandingPage_ByteArray1.Add(tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_CreateNewRecords_TryDecryptFavoriteIndicatorx.tempNewCacheItem);
                                
                                await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewAllCacheOverwrite(listModel_CampPasswordManagerEnterprise_LandingPage_ByteArray0);
                                await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewFavoriteCacheOverwrite(listModel_CampPasswordManagerEnterprise_LandingPage_ByteArray1);

                            }
                            else
                            {
                                List<Model_CampPasswordManagerEnterprise_LandingPage_ByteArray> listModel_CampPasswordManagerEnterprise_LandingPage_ByteArray = await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewAllCacheDownload();

                                listModel_CampPasswordManagerEnterprise_LandingPage_ByteArray.Add(tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_CreateNewRecords_TryDecryptFavoriteIndicatorx.tempNewCacheItem);

                                await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewAllCacheOverwrite(listModel_CampPasswordManagerEnterprise_LandingPage_ByteArray);
                            }

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, $"Soft update cache finished");
                        }
                        else
                        {
                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(tempModel_CampMemberServiceDynamicContext.SignalIRConnectionID, $"Cache NOT consistent");

                            if (tempMain_Cache_CampPasswordManagerEnterprise.Model_CampPasswordManagerEnterprise_CreateNewRecords_TryDecryptFavoriteIndicatorx.isFavoriteIndicated)
                            {
                                // Call for mode 0 cache

                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 1111");

                                RecievedRequest.Main_DataModel_FromClientx.Model_CreateNewRecordsx = null;

                                RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx = new Model_CampPasswordManagerEnterprise_FetchingFeeds
                                {
                                    fetchingMode = 0,

                                    isCallOnlyForCaching = true
                                };

                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 2222");

                                Camp_Password_Manager_Enterprise_Service hotCPMEService0 = new Camp_Password_Manager_Enterprise_Service(tempModel_CampMemberServiceDynamicContext, RecievedRequest);

                                (byte[] annonymousDataFallbackGlobal0, Main_Cache_CampPasswordManagerEnterprise tempMain_Cache_CampPasswordManagerEnterprise0) = await hotCPMEService0.RunService();

                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 3333");

                                tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All = tempMain_Cache_CampPasswordManagerEnterprise0.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All;

                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching FF0 Done");



                                // Call for mode 1 cache

                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 1111");

                                RecievedRequest.Main_DataModel_FromClientx.Model_CreateNewRecordsx = null;

                                RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx = new Model_CampPasswordManagerEnterprise_FetchingFeeds
                                {
                                    fetchingMode = 1,

                                    isCallOnlyForCaching = true
                                };

                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 2222");

                                Camp_Password_Manager_Enterprise_Service hotCPMEService1 = new Camp_Password_Manager_Enterprise_Service(tempModel_CampMemberServiceDynamicContext, RecievedRequest);

                                (byte[] annonymousDataFallbackGlobal1, Main_Cache_CampPasswordManagerEnterprise tempMain_Cache_CampPasswordManagerEnterprise1) = await hotCPMEService1.RunService();

                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 3333");

                                tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Favorite = tempMain_Cache_CampPasswordManagerEnterprise1.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Favorite;

                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching FF0 Done");

                            }
                            else
                            {
                                // Call for mode 0 cache

                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "CXXX 1111");

                                RecievedRequest.Main_DataModel_FromClientx.Model_CreateNewRecordsx = null;

                                RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx = new Model_CampPasswordManagerEnterprise_FetchingFeeds
                                {
                                    fetchingMode = 0,

                                    isCallOnlyForCaching = true
                                };

                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "CXXX 2222");

                                Camp_Password_Manager_Enterprise_Service hotCPMEService = new Camp_Password_Manager_Enterprise_Service(tempModel_CampMemberServiceDynamicContext, RecievedRequest);

                                (byte[] annonymousDataFallbackGlobal, Main_Cache_CampPasswordManagerEnterprise tempMain_Cache_CampPasswordManagerEnterprise0) = await hotCPMEService.RunService();

                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "CXXX 3333");

                                tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All = tempMain_Cache_CampPasswordManagerEnterprise0.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All;

                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching FF0 Done");
                            }


                        }

                    }

                    else if(RecievedRequest.Main_DataModel_FromClientx.Model_UpdateRecordsx != null)
                    {


                        if(tempMain_Cache_CampPasswordManagerEnterprise.isUpdateRecordsAFavorited)
                        {
                            // Call for mode 0 cache

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 1111");

                            RecievedRequest.Main_DataModel_FromClientx.Model_CreateNewRecordsx = null;

                            RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx = new Model_CampPasswordManagerEnterprise_FetchingFeeds
                            {
                                fetchingMode = 0,

                                isCallOnlyForCaching = true
                            };

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 2222");

                            Camp_Password_Manager_Enterprise_Service hotCPMEService0 = new Camp_Password_Manager_Enterprise_Service(tempModel_CampMemberServiceDynamicContext, RecievedRequest);

                            (byte[] annonymousDataFallbackGlobal0, Main_Cache_CampPasswordManagerEnterprise tempMain_Cache_CampPasswordManagerEnterprise0) = await hotCPMEService0.RunService();

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 3333");

                            tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All = tempMain_Cache_CampPasswordManagerEnterprise0.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All;

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching FF0 Done");



                            // Call for mode 1 cache

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 1111");

                            RecievedRequest.Main_DataModel_FromClientx.Model_CreateNewRecordsx = null;

                            RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx = new Model_CampPasswordManagerEnterprise_FetchingFeeds
                            {
                                fetchingMode = 1,

                                isCallOnlyForCaching = true
                            };

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 2222");

                            Camp_Password_Manager_Enterprise_Service hotCPMEService1 = new Camp_Password_Manager_Enterprise_Service(tempModel_CampMemberServiceDynamicContext, RecievedRequest);

                            (byte[] annonymousDataFallbackGlobal1, Main_Cache_CampPasswordManagerEnterprise tempMain_Cache_CampPasswordManagerEnterprise1) = await hotCPMEService1.RunService();

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 3333");

                            tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Favorite = tempMain_Cache_CampPasswordManagerEnterprise1.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Favorite;

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching FF0 Done");
                        }
                        else
                        {
                            // Call for mode 0 cache

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 1111");

                            RecievedRequest.Main_DataModel_FromClientx.Model_CreateNewRecordsx = null;

                            RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx = new Model_CampPasswordManagerEnterprise_FetchingFeeds
                            {
                                fetchingMode = 0,

                                isCallOnlyForCaching = true
                            };

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 2222");

                            Camp_Password_Manager_Enterprise_Service hotCPMEService0 = new Camp_Password_Manager_Enterprise_Service(tempModel_CampMemberServiceDynamicContext, RecievedRequest);

                            (byte[] annonymousDataFallbackGlobal0, Main_Cache_CampPasswordManagerEnterprise tempMain_Cache_CampPasswordManagerEnterprise0) = await hotCPMEService0.RunService();

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 3333");

                            tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All = tempMain_Cache_CampPasswordManagerEnterprise0.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All;

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching FF0 Done");
                        }
                    }

                    else if (RecievedRequest.Main_DataModel_FromClientx.Model_MoveRecordsToBINx != null)
                    {


                        if (tempMain_Cache_CampPasswordManagerEnterprise.isMoveRecordsToBinAFavorited)
                        {
                            // Call for mode 0 cache

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 1111");

                            RecievedRequest.Main_DataModel_FromClientx.Model_CreateNewRecordsx = null;

                            RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx = new Model_CampPasswordManagerEnterprise_FetchingFeeds
                            {
                                fetchingMode = 0,

                                isCallOnlyForCaching = true
                            };

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 2222");

                            Camp_Password_Manager_Enterprise_Service hotCPMEService0 = new Camp_Password_Manager_Enterprise_Service(tempModel_CampMemberServiceDynamicContext, RecievedRequest);

                            (byte[] annonymousDataFallbackGlobal0, Main_Cache_CampPasswordManagerEnterprise tempMain_Cache_CampPasswordManagerEnterprise0) = await hotCPMEService0.RunService();

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 3333");

                            tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All = tempMain_Cache_CampPasswordManagerEnterprise0.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All;

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching FF0 Done");



                            // Call for mode 1 cache

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 1111");

                            RecievedRequest.Main_DataModel_FromClientx.Model_CreateNewRecordsx = null;

                            RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx = new Model_CampPasswordManagerEnterprise_FetchingFeeds
                            {
                                fetchingMode = 1,

                                isCallOnlyForCaching = true
                            };

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 2222");

                            Camp_Password_Manager_Enterprise_Service hotCPMEService1 = new Camp_Password_Manager_Enterprise_Service(tempModel_CampMemberServiceDynamicContext, RecievedRequest);

                            (byte[] annonymousDataFallbackGlobal1, Main_Cache_CampPasswordManagerEnterprise tempMain_Cache_CampPasswordManagerEnterprise1) = await hotCPMEService1.RunService();

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 3333");

                            tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Favorite = tempMain_Cache_CampPasswordManagerEnterprise1.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Favorite;

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching FF0 Done");






                            // Call for mode 2 cache

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 1111");

                            RecievedRequest.Main_DataModel_FromClientx.Model_CreateNewRecordsx = null;

                            RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx = new Model_CampPasswordManagerEnterprise_FetchingFeeds
                            {
                                fetchingMode = 2,

                                isCallOnlyForCaching = true
                            };

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 2222");

                            Camp_Password_Manager_Enterprise_Service hotCPMEService2 = new Camp_Password_Manager_Enterprise_Service(tempModel_CampMemberServiceDynamicContext, RecievedRequest);

                            (byte[] annonymousDataFallbackGlobal2, Main_Cache_CampPasswordManagerEnterprise tempMain_Cache_CampPasswordManagerEnterprise2) = await hotCPMEService1.RunService();

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 3333");

                            tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Recycle = tempMain_Cache_CampPasswordManagerEnterprise2.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Favorite;

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching FF0 Done");


                        }
                        else
                        {
                            // Call for mode 0 cache

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 1111");

                            RecievedRequest.Main_DataModel_FromClientx.Model_CreateNewRecordsx = null;

                            RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx = new Model_CampPasswordManagerEnterprise_FetchingFeeds
                            {
                                fetchingMode = 0,

                                isCallOnlyForCaching = true
                            };

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 2222");

                            Camp_Password_Manager_Enterprise_Service hotCPMEService0 = new Camp_Password_Manager_Enterprise_Service(tempModel_CampMemberServiceDynamicContext, RecievedRequest);

                            (byte[] annonymousDataFallbackGlobal0, Main_Cache_CampPasswordManagerEnterprise tempMain_Cache_CampPasswordManagerEnterprise0) = await hotCPMEService0.RunService();

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 3333");

                            tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All = tempMain_Cache_CampPasswordManagerEnterprise0.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All;

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching FF0 Done");




                            // Call for mode 2 cache

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 1111");

                            RecievedRequest.Main_DataModel_FromClientx.Model_CreateNewRecordsx = null;

                            RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx = new Model_CampPasswordManagerEnterprise_FetchingFeeds
                            {
                                fetchingMode = 2,

                                isCallOnlyForCaching = true
                            };

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 2222");

                            Camp_Password_Manager_Enterprise_Service hotCPMEService1 = new Camp_Password_Manager_Enterprise_Service(tempModel_CampMemberServiceDynamicContext, RecievedRequest);

                            (byte[] annonymousDataFallbackGlobal1, Main_Cache_CampPasswordManagerEnterprise tempMain_Cache_CampPasswordManagerEnterprise1) = await hotCPMEService1.RunService();

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 3333");

                            tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Recycle = tempMain_Cache_CampPasswordManagerEnterprise1.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Favorite;

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching FF0 Done");
                        }

                    }

                    else if(RecievedRequest.Main_DataModel_FromClientx.Model_RecoverRecordsx != null)
                    {



                        if (tempMain_Cache_CampPasswordManagerEnterprise.isRecoverRecordsAFavorited)
                        {
                            // Call for mode 0 cache

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 1111");

                            RecievedRequest.Main_DataModel_FromClientx.Model_CreateNewRecordsx = null;

                            RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx = new Model_CampPasswordManagerEnterprise_FetchingFeeds
                            {
                                fetchingMode = 0,

                                isCallOnlyForCaching = true
                            };

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 2222");

                            Camp_Password_Manager_Enterprise_Service hotCPMEService0 = new Camp_Password_Manager_Enterprise_Service(tempModel_CampMemberServiceDynamicContext, RecievedRequest);

                            (byte[] annonymousDataFallbackGlobal0, Main_Cache_CampPasswordManagerEnterprise tempMain_Cache_CampPasswordManagerEnterprise0) = await hotCPMEService0.RunService();

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 3333");

                            tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All = tempMain_Cache_CampPasswordManagerEnterprise0.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All;

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching FF0 Done");



                            // Call for mode 1 cache

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 1111");

                            RecievedRequest.Main_DataModel_FromClientx.Model_CreateNewRecordsx = null;

                            RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx = new Model_CampPasswordManagerEnterprise_FetchingFeeds
                            {
                                fetchingMode = 1,

                                isCallOnlyForCaching = true
                            };

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 2222");

                            Camp_Password_Manager_Enterprise_Service hotCPMEService1 = new Camp_Password_Manager_Enterprise_Service(tempModel_CampMemberServiceDynamicContext, RecievedRequest);

                            (byte[] annonymousDataFallbackGlobal1, Main_Cache_CampPasswordManagerEnterprise tempMain_Cache_CampPasswordManagerEnterprise1) = await hotCPMEService1.RunService();

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 3333");

                            tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Favorite = tempMain_Cache_CampPasswordManagerEnterprise1.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Favorite;

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching FF0 Done");






                            // Call for mode 2 cache

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 1111");

                            RecievedRequest.Main_DataModel_FromClientx.Model_CreateNewRecordsx = null;

                            RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx = new Model_CampPasswordManagerEnterprise_FetchingFeeds
                            {
                                fetchingMode = 2,

                                isCallOnlyForCaching = true
                            };

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 2222");

                            Camp_Password_Manager_Enterprise_Service hotCPMEService2 = new Camp_Password_Manager_Enterprise_Service(tempModel_CampMemberServiceDynamicContext, RecievedRequest);

                            (byte[] annonymousDataFallbackGlobal2, Main_Cache_CampPasswordManagerEnterprise tempMain_Cache_CampPasswordManagerEnterprise2) = await hotCPMEService1.RunService();

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 3333");

                            tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Recycle = tempMain_Cache_CampPasswordManagerEnterprise2.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Favorite;

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching FF0 Done");


                        }
                        else
                        {
                            // Call for mode 0 cache

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 1111");

                            RecievedRequest.Main_DataModel_FromClientx.Model_CreateNewRecordsx = null;

                            RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx = new Model_CampPasswordManagerEnterprise_FetchingFeeds
                            {
                                fetchingMode = 0,

                                isCallOnlyForCaching = true
                            };

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 2222");

                            Camp_Password_Manager_Enterprise_Service hotCPMEService0 = new Camp_Password_Manager_Enterprise_Service(tempModel_CampMemberServiceDynamicContext, RecievedRequest);

                            (byte[] annonymousDataFallbackGlobal0, Main_Cache_CampPasswordManagerEnterprise tempMain_Cache_CampPasswordManagerEnterprise0) = await hotCPMEService0.RunService();

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 3333");

                            tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All = tempMain_Cache_CampPasswordManagerEnterprise0.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All;

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching FF0 Done");




                            // Call for mode 2 cache

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 1111");

                            RecievedRequest.Main_DataModel_FromClientx.Model_CreateNewRecordsx = null;

                            RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx = new Model_CampPasswordManagerEnterprise_FetchingFeeds
                            {
                                fetchingMode = 2,

                                isCallOnlyForCaching = true
                            };

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 2222");

                            Camp_Password_Manager_Enterprise_Service hotCPMEService1 = new Camp_Password_Manager_Enterprise_Service(tempModel_CampMemberServiceDynamicContext, RecievedRequest);

                            (byte[] annonymousDataFallbackGlobal1, Main_Cache_CampPasswordManagerEnterprise tempMain_Cache_CampPasswordManagerEnterprise1) = await hotCPMEService1.RunService();

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 3333");

                            tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Recycle = tempMain_Cache_CampPasswordManagerEnterprise1.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Favorite;

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching FF0 Done");
                        }





                    }

                    else if(RecievedRequest.Main_DataModel_FromClientx.Model_PermanentDeleteRecordsx != null)
                    {

                        // Call for mode 2 cache

                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 1111");

                        RecievedRequest.Main_DataModel_FromClientx.Model_CreateNewRecordsx = null;

                        RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx = new Model_CampPasswordManagerEnterprise_FetchingFeeds
                        {
                            fetchingMode = 2,

                            isCallOnlyForCaching = true
                        };

                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 2222");

                        Camp_Password_Manager_Enterprise_Service hotCPMEService0 = new Camp_Password_Manager_Enterprise_Service(tempModel_CampMemberServiceDynamicContext, RecievedRequest);

                        (byte[] annonymousDataFallbackGlobal0, Main_Cache_CampPasswordManagerEnterprise tempMain_Cache_CampPasswordManagerEnterprise0) = await hotCPMEService0.RunService();

                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 3333");

                        tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Recycle = tempMain_Cache_CampPasswordManagerEnterprise0.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Favorite;

                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching FF0 Done");
                    }





                    else if(RecievedRequest.Main_DataModel_FromClientx.Model_CopyPasswordx != null)
                    {


                        if (tempMain_Cache_CampPasswordManagerEnterprise.isCopyPasswordAFavorited)
                        {
                            // Call for mode 0 cache

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 1111");

                            RecievedRequest.Main_DataModel_FromClientx.Model_CreateNewRecordsx = null;

                            RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx = new Model_CampPasswordManagerEnterprise_FetchingFeeds
                            {
                                fetchingMode = 0,

                                isCallOnlyForCaching = true
                            };

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 2222");

                            Camp_Password_Manager_Enterprise_Service hotCPMEService0 = new Camp_Password_Manager_Enterprise_Service(tempModel_CampMemberServiceDynamicContext, RecievedRequest);

                            (byte[] annonymousDataFallbackGlobal0, Main_Cache_CampPasswordManagerEnterprise tempMain_Cache_CampPasswordManagerEnterprise0) = await hotCPMEService0.RunService();

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 3333");

                            tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All = tempMain_Cache_CampPasswordManagerEnterprise0.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All;

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching FF0 Done");



                            // Call for mode 1 cache

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 1111");

                            RecievedRequest.Main_DataModel_FromClientx.Model_CreateNewRecordsx = null;

                            RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx = new Model_CampPasswordManagerEnterprise_FetchingFeeds
                            {
                                fetchingMode = 1,

                                isCallOnlyForCaching = true
                            };

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 2222");

                            Camp_Password_Manager_Enterprise_Service hotCPMEService1 = new Camp_Password_Manager_Enterprise_Service(tempModel_CampMemberServiceDynamicContext, RecievedRequest);

                            (byte[] annonymousDataFallbackGlobal1, Main_Cache_CampPasswordManagerEnterprise tempMain_Cache_CampPasswordManagerEnterprise1) = await hotCPMEService1.RunService();

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "BXXX 3333");

                            tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Favorite = tempMain_Cache_CampPasswordManagerEnterprise1.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Favorite;

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching FF0 Done");
                        }
                        else
                        {
                            // Call for mode 0 cache

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 1111");

                            RecievedRequest.Main_DataModel_FromClientx.Model_CreateNewRecordsx = null;

                            RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx = new Model_CampPasswordManagerEnterprise_FetchingFeeds
                            {
                                fetchingMode = 0,

                                isCallOnlyForCaching = true
                            };

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 2222");

                            Camp_Password_Manager_Enterprise_Service hotCPMEService0 = new Camp_Password_Manager_Enterprise_Service(tempModel_CampMemberServiceDynamicContext, RecievedRequest);

                            (byte[] annonymousDataFallbackGlobal0, Main_Cache_CampPasswordManagerEnterprise tempMain_Cache_CampPasswordManagerEnterprise0) = await hotCPMEService0.RunService();

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "AXXX 3333");

                            tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All = tempMain_Cache_CampPasswordManagerEnterprise0.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All;

                            Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching FF0 Done");
                        }



                    }











                    if (RecievedRequest.Main_DataModel_FromClientx.Model_FetchingFeedsx != null)
                    {
                        try
                        {
                            bool isGettingNewDataFromFallback;

                            if (tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All != null || tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Favorite != null || tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Recycle != null)
                            {
                                isGettingNewDataFromFallback = true;
                            }
                            else
                            {
                                isGettingNewDataFromFallback = false;
                            }

                            if (isGettingNewDataFromFallback)
                            {
                                Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Fetching feed feeds visible for cache");

                                CampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency = new CampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency(tempModel_CampMemberServiceDynamicContext);



                                // Update cache if found new data assigned.

                                if (tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All.Count() > 0)
                                {
                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching mode 0");

                                    await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewAllCacheOverwrite(tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_All);

                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching mode 0 finished");
                                }

                                if (tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Favorite.Count() > 0)
                                {
                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching mode 1");

                                    await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewFavoriteCacheOverwrite(tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Favorite);

                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching mode 1 finished");
                                }

                                if (tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Recycle.Count() > 0)
                                {
                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching mode 2");

                                    await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.ListviewRecycleCacheOverwrite(tempMain_Cache_CampPasswordManagerEnterprise.ListModel_CampPasswordManagerEnterprise_LandingPage_ByteArrayx_Recycle);

                                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Caching mode 2 finished");
                                }




                            }
                            else
                            {

                            }
                        }
                        catch (Exception ex)
                        {

                        }

                    }

                }
            }
            catch (Exception ex)
            {
                Configuration_CampPasswordManagerEnterprise_ClientRequestResults tempConfiguration_CPMEClientRequestResults = new Configuration_CampPasswordManagerEnterprise_ClientRequestResults
                {
                    Configuration_CampMember_ServiceResultx = new Configuration_CampMember_ServiceResult
                    {
                        ErrorMessages = $"Global error : {ex.Message}"
                    },
                    Main_DataModel_FromServerx = new Main_CampPasswordManagerEnterprise_DataModel_FromServer(),
                    JobID = RecievedRequest.JobID
                };

                byte[] protobufData;
                using (var stream = new MemoryStream())
                {
                    Serializer.Serialize(stream, tempConfiguration_CPMEClientRequestResults);
                    protobufData = stream.ToArray();
                }

                await Clients.Caller.SendAsync("CampPasswordManagerEnterprise_Response", protobufData);

                Program.CampConnectServiceInstance.CampMember_SendRuntime_Error_ToSpecificConnection(Context.ConnectionId, "Service error");
            }
        }

        public async Task CampWorthwhileLogs_Request_DataGram(byte[] requestData)
        {
            HttpRequest? req = Context.GetHttpContext()?.Request;

            // 1. Extract token
            string? token = null;
            if (req != null && req.Headers.ContainsKey("Authorization"))
            {
                var authHeader = req.Headers["Authorization"].ToString();
                if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                    token = authHeader.Substring("Bearer ".Length).Trim();
            }

            if (string.IsNullOrEmpty(token))
            {
                Program.CampConnectServiceInstance.CampMember_SendRuntime_Denied_ClientRequestResultToSpecificConnection(
                    Context.ConnectionId, "Token missing");
                Context.Abort();
                return;
            }

            // 2. Validate via central Keycloak service
            (bool isTokanValid, string logsResults) = await Program.hotRedHat_Keycloak_ConfidentialServiceAccount_agency.ValidateAuthTokenAsync(token);


            byte[]? annonymousData = null;
            int? callIdentification = null;


            string internaluser_identifier = Server_UserProfileReaderMachine.GetUserID(req);
            byte[] internaluser_identifiersha256 = ByteArrayAndConversionMachine.DoComputeStringToSHA256Hash(internaluser_identifier);
            string internaluser_email = Server_UserProfileReaderMachine.GetEmail(req);
            string internaluser_identifiersha256HEX = BitConverter.ToString(internaluser_identifiersha256).Replace("-", "").ToLowerInvariant();

            Model_CampMember_AccountAgencyConsultResults tempModel_AccountAgencyConsultResults = new Model_CampMember_AccountAgencyConsultResults();

            Model_CampMember_ServiceContext tempModel_CampMemberServiceDynamicContext = new Model_CampMember_ServiceContext
            {
                user_Identifier = internaluser_identifier,
                user_IdentifierSHA256 = internaluser_identifiersha256,
                user_IdentifierSHAHEX = internaluser_identifiersha256HEX,
                user_Email = internaluser_email,
                Model_AccountAgencyConsultResultsx = tempModel_AccountAgencyConsultResults,
                HttpRequestx = req,
                SignalIRConnectionID = Context.ConnectionId
            };

            Main_CampWorthwhileLogs_Request_FromClient RecievedRequest;
            using (var ms = new MemoryStream(requestData))
            {
                RecievedRequest = Serializer.Deserialize<Main_CampWorthwhileLogs_Request_FromClient>(ms);
            }

            try
            {
                if (!isTokanValid)
                {
                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Denied_ClientRequestResultToSpecificConnection(Context.ConnectionId, "Session expired");

                    Configuration_CampWorthwhileLogs_ClientRequestResults tempConfiguration_CWWClientRequestResults = new Configuration_CampWorthwhileLogs_ClientRequestResults
                    {
                        Configuration_CampMember_ServiceResultx = new Configuration_CampMember_ServiceResult()
                        {
                            isCampMemberServiceConnectionDenied = true
                        },
                        Main_CWW_DataModel_FromServerx = new Main_CampWorthwhileLogs_DataModel_FromServer()
                        {

                        },
                        JobID = RecievedRequest.JobID
                    };

                    byte[] protobufData;
                    using (var stream = new MemoryStream())
                    {
                        Serializer.Serialize(stream, tempConfiguration_CWWClientRequestResults);
                        protobufData = stream.ToArray();
                    }

                    await Clients.Caller.SendAsync("CWWResponse", protobufData);
                }
                else
                {
                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Service received on server");

                    Camp_Worthwhile_Logs_Service hotCamp_Worthwhile_Logs_Service = new Camp_Worthwhile_Logs_Service(tempModel_CampMemberServiceDynamicContext, RecievedRequest);

                    annonymousData = await hotCamp_Worthwhile_Logs_Service.RunService();

                    await Clients.Caller.SendAsync("CWWResponse", annonymousData);

                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Success_ToSpecificConnection(Context.ConnectionId, "Returned response");
                }
            }
            catch (Exception ex)
            {
                Configuration_CampWorthwhileLogs_ClientRequestResults tempConfiguration_CWWClientRequestResults = new Configuration_CampWorthwhileLogs_ClientRequestResults
                {
                    Configuration_CampMember_ServiceResultx = new Configuration_CampMember_ServiceResult()
                    {
                        ErrorMessages = $"Global error : {ex.Message}"
                    },
                    Main_CWW_DataModel_FromServerx = new Main_CampWorthwhileLogs_DataModel_FromServer()
                    {

                    },
                    JobID = RecievedRequest.JobID
                };

                byte[] protobufData;
                using (var stream = new MemoryStream())
                {
                    Serializer.Serialize(stream, tempConfiguration_CWWClientRequestResults);
                    protobufData = stream.ToArray();
                }

                await Clients.Caller.SendAsync("CWWResponse", protobufData);

                Program.CampConnectServiceInstance.CampMember_SendRuntime_Error_ToSpecificConnection(Context.ConnectionId, "Service error");
            }
        }

        public async Task CampDating_Request_DataGram(byte[] requestData)
        {
            HttpRequest? req = Context.GetHttpContext()?.Request;

            // 1. Extract token
            string? token = null;
            if (req != null && req.Headers.ContainsKey("Authorization"))
            {
                var authHeader = req.Headers["Authorization"].ToString();
                if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                    token = authHeader.Substring("Bearer ".Length).Trim();
            }

            if (string.IsNullOrEmpty(token))
            {
                Program.CampConnectServiceInstance.CampMember_SendRuntime_Denied_ClientRequestResultToSpecificConnection(
                    Context.ConnectionId, "Token missing");
                Context.Abort();
                return;
            }

            // 2. Validate via central Keycloak service
            (bool isTokanValid, string logsResults) = await Program.hotRedHat_Keycloak_ConfidentialServiceAccount_agency.ValidateAuthTokenAsync(token);

            byte[]? annonymousData = null;
            int? callIdentification = null;

            string internaluser_identifier = Server_UserProfileReaderMachine.GetUserID(req);
            byte[] internaluser_identifiersha256 = ByteArrayAndConversionMachine.DoComputeStringToSHA256Hash(internaluser_identifier);
            string internaluser_email = Server_UserProfileReaderMachine.GetEmail(req);
            string internaluser_identifiersha256HEX = BitConverter.ToString(ByteArrayAndConversionMachine.DoComputeStringToSHA256Hash(internaluser_identifier)).Replace("-", "").ToLowerInvariant();

            Model_CampMember_AccountAgencyConsultResults tempModel_AccountAgencyConsultResults = new Model_CampMember_AccountAgencyConsultResults();

            Model_CampMember_ServiceContext tempModel_CampMemberServiceDynamicContext = new Model_CampMember_ServiceContext
            {
                user_Identifier = internaluser_identifier,
                user_IdentifierSHA256 = internaluser_identifiersha256,
                user_IdentifierSHAHEX = internaluser_identifiersha256HEX,
                user_Email = internaluser_email,
                Model_AccountAgencyConsultResultsx = tempModel_AccountAgencyConsultResults,
                HttpRequestx = req,
                SignalIRConnectionID = Context.ConnectionId
            };

            // Deserialize input protobuf bytes to your request model
            Main_CampDating_Request_FromClient RecievedRequest;
            using (var ms = new MemoryStream(requestData))
            {
                RecievedRequest = Serializer.Deserialize<Main_CampDating_Request_FromClient>(ms);
            }

            try
            {
                if (!isTokanValid)
                {
                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Error_ToSpecificConnection(Context.ConnectionId, "Session expired");

                    Configuration_CampDating_ClientRequestResults tempConfiguration_CampDating_ClientRequestResults = new Configuration_CampDating_ClientRequestResults
                    {
                        Configuration_CampMember_ServiceResultx = new Configuration_CampMember_ServiceResult
                        {
                            isCampMemberServiceConnectionDenied = true
                        },
                        Main_CampDating_DataModel_FromServerx = new Main_CampDating_DataModel_FromServer
                        {

                        },

                        JobID = RecievedRequest.JobID
                    };

                    byte[] protobufData;
                    using (var stream = new MemoryStream())
                    {
                        Serializer.Serialize(stream, tempConfiguration_CampDating_ClientRequestResults);
                        protobufData = stream.ToArray();
                    }

                    await Clients.Caller.SendAsync("CDTResponse", protobufData);
                }
                else
                {
                    if(Program.isExternalWorkerDeviceWaitingForAJob)
                    {
                        string connectionId = Context.ConnectionId;


                        Model_CampMember_ServiceContext_Minimal tempModel_CampMember_ServiceContext_Minimal = new Model_CampMember_ServiceContext_Minimal()
                        {
                            user_Identifier = tempModel_CampMemberServiceDynamicContext.user_Identifier,

                            user_IdentifierSHA256 = tempModel_CampMemberServiceDynamicContext.user_IdentifierSHA256,

                            user_IdentifierSHAHEX = tempModel_CampMemberServiceDynamicContext.user_IdentifierSHAHEX,

                            user_Email = tempModel_CampMemberServiceDynamicContext.user_Email,

                            Model_AccountAgencyConsultResultsx = tempModel_CampMemberServiceDynamicContext.Model_AccountAgencyConsultResultsx
                        };


                        Model_PowerJob_PowerContributorJob tempModel_PowerContributorJob = new Model_PowerJob_PowerContributorJob()
                        {
                            JobIdentification = Guid.NewGuid(),

                            ConnectionID = connectionId,

                            Job = RecievedRequest,

                            ServiceContext = tempModel_CampMember_ServiceContext_Minimal,

                            DataContext = new Main_PowerJob_DataContext()
                            {
                                Model_CDT_PowerJob_DataContextx = new Model_PowerJob_CampDating_DataContext()
                                {
                                    listModel_CampDating_HotFeedProfile_Server = new List<Model_CampDating_HotFeedProfile_Server>(),
                                }

                            }
                        };





                        if(RecievedRequest.Main_CampDating_DataModel_FromClientx.Model_CampDating_FetchingCDTFeedsx != null)
                        {
                            CampCommercialServer_Azure_Blob_CampBasement_CampMember_agency hothotBlob_Agency_CampMemberBlob = new CampCommercialServer_Azure_Blob_CampBasement_CampMember_agency(tempModel_CampMemberServiceDynamicContext);

                            bool? IsUserDefinedFixLocation = await hothotBlob_Agency_CampMemberBlob.IsUserLatitudeDefinedAsync();

                            if (IsUserDefinedFixLocation == false)
                            {

                            }
                            else
                            {
                                CampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency = new CampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency(tempModel_CampMemberServiceDynamicContext);

                                List<Model_CampMember_RSAServerSide_AESEncrypted> tempModel_RSAServerSide = await hotCampCommercialServer_Azure_BlobPremium_CampBasement_CampMember_agency.CPMEUserKeysDownload();




                                CampCommercialServer_Crypto_agency hotCampCryptoAgency = new CampCommercialServer_Crypto_agency(tempModel_CampMemberServiceDynamicContext);

                                await hotCampCryptoAgency.RetriveAKey(3, null, null,null, true);


                                tempModel_PowerContributorJob.DataContext.Model_CDT_PowerJob_DataContextx.PublicKey = hotCampCryptoAgency.keyPair.PublicKey;

                                tempModel_PowerContributorJob.DataContext.Model_CDT_PowerJob_DataContextx.isUserDefinedLocation = true;

                                //tempModel_PowerContributorJob.DataContext.Model_CDT_PowerJob_DataContextx.listModel_CampDating_HotFeedProfile_Server = await hothotBlob_Agency_CampMemberBlob.GetNearbyHotFeedProfilesAsync(20000, null);
                            }
                        }


                        Program.CDTRequestList.Add(tempModel_PowerContributorJob);

                        await Clients.Client(connectionId).SendAsync("YourMethodName", "Job added");
                    }
                    else
                    {
                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Service received on server");

                        Camp_Dating_Service hotCamp_Dating_Service = new Camp_Dating_Service(tempModel_CampMemberServiceDynamicContext, RecievedRequest);

                        annonymousData = await hotCamp_Dating_Service.RunService();

                        // Send back to the caller
                        await Clients.Caller.SendAsync("CDTResponse", annonymousData);

                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Success_ToSpecificConnection(Context.ConnectionId, "Returned response");
                    }
                }
            }
            catch (Exception ex)
            {
                Configuration_CampDating_ClientRequestResults tempConfiguration_CampDating_ClientRequestResults = new Configuration_CampDating_ClientRequestResults
                {
                    Configuration_CampMember_ServiceResultx = new Configuration_CampMember_ServiceResult()
                    {
                        ErrorMessages = $"Global error : {ex.Message}"
                    },
                    Main_CampDating_DataModel_FromServerx = new Main_CampDating_DataModel_FromServer
                    {

                    },

                    JobID = RecievedRequest.JobID
                };

                byte[] protobufData;
                using (var stream = new MemoryStream())
                {
                    Serializer.Serialize(stream, tempConfiguration_CampDating_ClientRequestResults);
                    protobufData = stream.ToArray();
                }

                await Clients.Caller.SendAsync("CDTResponse", protobufData);

                Program.CampConnectServiceInstance.CampMember_SendRuntime_Error_ToSpecificConnection(Context.ConnectionId, "Service error");
            }
        }




        public async Task CampStore_Request_DataGram(byte[] requestData)
        {
            HttpRequest? req = Context.GetHttpContext()?.Request;

            // 1. Extract token
            string? token = null;
            if (req != null && req.Headers.ContainsKey("Authorization"))
            {
                var authHeader = req.Headers["Authorization"].ToString();
                if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                    token = authHeader.Substring("Bearer ".Length).Trim();
            }

            if (string.IsNullOrEmpty(token))
            {
                Program.CampConnectServiceInstance.CampMember_SendRuntime_Denied_ClientRequestResultToSpecificConnection(
                    Context.ConnectionId, "Token missing");
                Context.Abort();
                return;
            }

            // 2. Validate via central Keycloak service
            (bool isTokanValid, string logsResults) = await Program.hotRedHat_Keycloak_ConfidentialServiceAccount_agency.ValidateAuthTokenAsync(token);

            try
            {
                byte[]? annonymousData = null;
                int? callIdentification = null;

                string internaluser_identifier = Server_UserProfileReaderMachine.GetUserID(req);
                byte[] internaluser_identifiersha256 = ByteArrayAndConversionMachine.DoComputeStringToSHA256Hash(internaluser_identifier);
                string internaluser_email = Server_UserProfileReaderMachine.GetEmail(req);
                string internaluser_identifiersha256HEX = BitConverter.ToString(ByteArrayAndConversionMachine.DoComputeStringToSHA256Hash(internaluser_identifier)).Replace("-", "").ToLowerInvariant();

                Model_CampMember_AccountAgencyConsultResults tempModel_AccountAgencyConsultResults = new Model_CampMember_AccountAgencyConsultResults();

                Model_CampMember_ServiceContext tempModel_CampMemberServiceDynamicContext = new Model_CampMember_ServiceContext
                {
                    user_Identifier = internaluser_identifier,
                    user_IdentifierSHA256 = internaluser_identifiersha256,
                    user_IdentifierSHAHEX = internaluser_identifiersha256HEX,
                    user_Email = internaluser_email,
                    Model_AccountAgencyConsultResultsx = tempModel_AccountAgencyConsultResults,
                    HttpRequestx = req,
                    SignalIRConnectionID = Context.ConnectionId
                };

                // Deserialize input protobuf bytes to your request model
                Main_CampStore_Request_FromClient RecievedRequest;
                using (var ms = new MemoryStream(requestData))
                {
                    RecievedRequest = Serializer.Deserialize<Main_CampStore_Request_FromClient>(ms);
                }

                try
                {
                    if (!isTokanValid)
                    {
                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Denied_ClientRequestResultToSpecificConnection(Context.ConnectionId, "Session expired");

                        Configuration_CampStore_ClientRequestResults tempConfiguration_CampDating_ClientRequestResults = new Configuration_CampStore_ClientRequestResults
                        {
                            Configuration_CampMember_ServiceResultx = new Configuration_CampMember_ServiceResult
                            {
                                isCampMemberServiceConnectionDenied = true
                            },
                            Main_CampStore_DataModel_FromServerx = new Main_CampStore_DataModel_FromServer
                            {

                            },

                            JobID = RecievedRequest.JobID
                        };

                        byte[] protobufData;
                        using (var stream = new MemoryStream())
                        {
                            Serializer.Serialize(stream, tempConfiguration_CampDating_ClientRequestResults);
                            protobufData = stream.ToArray();
                        }

                        await Clients.Caller.SendAsync("CampStore_Response", protobufData);
                    }
                    else
                    {
                        //string azp = Context.User?.Claims.FirstOrDefault(c => c.Type == "azp")?.Value;
                        //if (azp == "CPMEWindows")
                        //{
                        //    Program.CampConnectServiceInstance.CampDating_SendTESTMessageToSpecificConnection(Context.ConnectionId, "TEST CPMEWindows");
                        //}

                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Processing_ToSpecificConnection(Context.ConnectionId, "Service received on server");

                        CampMember_CampStore_Service hotCampMember_CampStore_Service = new CampMember_CampStore_Service(tempModel_CampMemberServiceDynamicContext, RecievedRequest);

                        annonymousData = await hotCampMember_CampStore_Service.RunService();

                        await Clients.Caller.SendAsync("CampStore_Response", annonymousData);

                        Program.CampConnectServiceInstance.CampMember_SendRuntime_Success_ToSpecificConnection(Context.ConnectionId, "Returned response");
                    }
                }
                catch (Exception ex)
                {
                    await Program.CampConnectServiceInstance.CampDating_SendRuntime_Debug_MessageToSpecificConnection(Context.ConnectionId, $"Error {ex.Message}");

                    Configuration_CampDating_ClientRequestResults tempConfiguration_CampDating_ClientRequestResults = new Configuration_CampDating_ClientRequestResults
                    {
                        Configuration_CampMember_ServiceResultx = new Configuration_CampMember_ServiceResult()
                        {
                            ErrorMessages = $"Global error : {ex.Message}"
                        },
                        Main_CampDating_DataModel_FromServerx = new Main_CampDating_DataModel_FromServer
                        {

                        },

                        JobID = RecievedRequest.JobID
                    };

                    byte[] protobufData;
                    using (var stream = new MemoryStream())
                    {
                        Serializer.Serialize(stream, tempConfiguration_CampDating_ClientRequestResults);
                        protobufData = stream.ToArray();
                    }

                    await Clients.Caller.SendAsync("CampStore_Response", protobufData);

                    Program.CampConnectServiceInstance.CampMember_SendRuntime_Error_ToSpecificConnection(Context.ConnectionId, "Service error");
                }
            }
            catch (Exception ex)
            {
                await Program.CampConnectServiceInstance.CampDating_SendRuntime_Debug_MessageToSpecificConnection(Context.ConnectionId, $"CampStore_Request_DataGram errpr : {ex.Message}");

                Program.CampConnectServiceInstance.CampMember_SendRuntime_Error_ToSpecificConnection(Context.ConnectionId, "Service error");
            }
        }











        [Authorize(AuthenticationSchemes = "PowerContributeScheme")]
        public async Task<string> TestOracle()
        {
            //var configPath = "/root/.oci/config"; // your config file path
            //var compartmentId = "ocid1.compartment.oc1..aaaaaaaa7uk24z5x5ti4lx6efyoklqzrugjecnlqvftrxjrwri532zbcnu5a";

            //var storageService = new OracleObjectStorageService(configPath);
            //string result = await storageService.ListBucketsAsync(compartmentId);

            //Console.WriteLine(result);




            return null;

        }

        [Authorize(AuthenticationSchemes = "PowerContributeScheme")]
        public async Task<byte[]> RequestPowerJob()
        {
            byte[] rawData;
            try
            {
                Model_CampMember_ServiceContext tempModel_CampMember_ServiceContext = new Model_CampMember_ServiceContext();

                CampCommercialServer_Azure_Blob_CampBasement_CampMember_agency hotBlob_Agency_CampMemberBlob = new CampCommercialServer_Azure_Blob_CampBasement_CampMember_agency(tempModel_CampMember_ServiceContext);

                //Model_PowerContributorJob jobItem = Program.CDTRequestList.First(x => x.ProcessedData == null || x.ProcessedData.Length == 0);



                Model_PowerJob_PowerContributorJob jobItem = Program.CDTRequestList.First(
    x => (x.ProcessedData == null || x.ProcessedData.Length == 0) &&
         x.Job?.Main_CampDating_DataModel_FromClientx?.Model_CampDating_FetchingCDTFeedsx != null);





                string connectionID = jobItem.ConnectionID;

                jobItem.ConnectionID = null;

                using (var stream = new MemoryStream())
                {
                    Serializer.Serialize(stream, jobItem);
                    rawData = stream.ToArray();
                }

                jobItem.ConnectionID = connectionID;

                return rawData;
            }
            catch (Exception ex)
            {
                await Clients.Caller.SendAsync("ReceiveLog", $"Error : {ex.Message}");

                return null;
            }
        }

        [Authorize(AuthenticationSchemes = "PowerContributeScheme")]
        public async Task PowerClientProduct_Datagram(byte[] powerJob)
        {
            try
            {
                Model_PowerJob_PowerContributorJob receivedRequest;
                using (var ms = new MemoryStream(powerJob))
                {
                    receivedRequest = Serializer.Deserialize<Model_PowerJob_PowerContributorJob>(ms);
                }

                var matchedJob = Program.CDTRequestList.FirstOrDefault(x => x.JobIdentification == receivedRequest.JobIdentification);





                await Clients.Caller.SendAsync("CDTResponse", receivedRequest.ProcessedData);
            }
            catch (Exception ex)
            {
                await Clients.Caller.SendAsync("ReceiveLog", $"Error : {ex.Message}");
            }
        }












    }












}