use std::io::Read;
use std::sync::mpsc::{channel, Sender};

use threadpool::ThreadPool;

use config::Config;
use crate::build_request;
use crate::Request;
use crate::Result;
use yubicoerror::YubicoError;
use reqwest::{ClientBuilder, Client};
use reqwest::header::{USER_AGENT, HeaderMap, HeaderValue};
use std::sync::Arc;

pub fn verify<S>(otp: S, config: Config) -> Result<String>
    where S: Into<String>
{
    SyncVerifier::new(config)?
        .verify(otp)
}

pub struct SyncVerifier {
    client: Arc<Client>,
    thread_pool: ThreadPool,
    config: Config,
}

impl SyncVerifier {
    pub fn new(config: Config) -> Result<SyncVerifier> {
        let number_of_hosts = config.api_hosts.len();
        let thread_pool = ThreadPool::new(number_of_hosts);

        let mut headers = HeaderMap::new();
        let value = HeaderValue::from_str(&config.user_agent)
            .map_err(|_err| {
                YubicoError::InvalidUserAgent
            })?;
        headers.insert(USER_AGENT, value);

        let client = ClientBuilder::new()
            .timeout(config.request_timeout)
            .default_headers(headers)
            .build()
            .map_err(|err|{
                YubicoError::HTTPClientError(err)
            })?;

        Ok(SyncVerifier {
            config,
            thread_pool,
            client: Arc::new(client),
        })
    }

    pub fn verify<S>(&self, otp: S) -> Result<String>
        where S: Into<String>
    {
        let request = build_request(otp, &self.config)?;

        let (tx, rx) = channel();

        for api_host in &self.config.api_hosts {
            let processor = RequestProcessor {
                client: self.client.clone(),
                sender: tx.clone(),
                api_host: api_host.clone(),
                request: request.clone(),
            };

            self.thread_pool.execute(move || {
                processor.consume();
            });
        }

        let mut success = false;
        let mut results: Vec<Result<()>> = Vec::new();
        for _ in 0..self.config.api_hosts.len() {
            match rx.recv() {
                Ok(result) =>  {
                    match result {
                        Ok(_) => {
                            results.truncate(0);
                            success = true;
                        },
                        Err(_) => {
                            results.push(result);
                        },
                    }
                },
                Err(e) => {
                    results.push(Err(YubicoError::ChannelError(e)));
                    break
                },
            }
        }

        if success {
            Ok("The OTP is valid.".into())
        } else {
            let result = results.pop().unwrap();
            Err(result.unwrap_err())
        }
    }
}

struct RequestProcessor {
    client: Arc<Client>,
    sender: Sender<Result<()>>,
    api_host: String,
    request: Request,
}

impl RequestProcessor {
    fn consume(self) {
        match self.get() {
            Ok(()) => {
                self.sender.send(Ok(())).unwrap();
            },
            Err(e) => {
                self.sender.send(Err(e)).unwrap();
            }
        }
    }

    fn get(&self) -> Result<()> {
        let url = self.request.build_url(&self.api_host);

        let mut response = self.client
            .get(url.as_str())
            .send()?;

        let mut data = String::new();
        response.read_to_string(&mut data)?;

        self.request.response_verifier.verify_response(data)
    }
}