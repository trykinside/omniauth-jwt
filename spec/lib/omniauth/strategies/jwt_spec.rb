require 'spec_helper'

shared_examples 'request phase' do
  it 'should redirect to the configured login url' do
    get '/auth/jwt'
    expect(last_response.status).to eq(302)
    expect(last_response.headers['Location']).to eq('http://example.com/login')
  end
end

shared_examples 'callback phase' do
  context 'callback phase' do
    it 'should decode the response' do
      encoded = encode({name: 'Bob', email: 'steve@example.com'})

      get '/auth/jwt/callback?jwt=' + encoded
      expect(response_json["info"]["email"]).to eq("steve@example.com")
    end

    it 'should not work without required fields' do
      encoded = encode({name: 'Steve'})
      get '/auth/jwt/callback?jwt=' + encoded
      expect(last_response.status).to eq(302)
    end
    
    it 'should assign the uid' do
      encoded = encode({name: 'Steve', email: 'dude@awesome.com'})
      get '/auth/jwt/callback?jwt=' + encoded
      expect(response_json["uid"]).to eq('dude@awesome.com')
    end
    
  end
end

describe OmniAuth::Strategies::JWT do
  let(:response_json){ MultiJson.load(last_response.body) }

  context "RS256 algorithm" do
    let(:secret_key) { OpenSSL::PKey::RSA.new(file_fixture("private_key.pem").read) }
    let(:public_key) { secret_key.public_key }

    let(:args) { [public_key, {auth_url: 'http://example.com/login', algorithm: 'RS256'}]}

    def encode(claim)
      JWT.encode(claim, secret_key,  'RS256')
    end

    let(:app){
      the_args = args
      Rack::Builder.new do |b|
        b.use Rack::Session::Cookie, secret: 'sekrit'
        b.use OmniAuth::Strategies::JWT, *the_args
        b.run lambda{|env| [200, {}, [(env['omniauth.auth'] || {}).to_json]]}
      end
    }

    it_behaves_like "request phase"

    it_behaves_like 'callback phase'
  end

  context "default arguments" do
    let(:args){ ['imasecret', {auth_url: 'http://example.com/login'}] }
    
    def encode(claim)
      JWT.encode(claim, 'imasecret')
    end

    let(:app){
      the_args = args
      Rack::Builder.new do |b|
        b.use Rack::Session::Cookie, secret: 'sekrit'
        b.use OmniAuth::Strategies::JWT, *the_args
        b.run lambda{|env| [200, {}, [(env['omniauth.auth'] || {}).to_json]]}
      end
    }
    
    it_behaves_like "request phase"

    context 'callback phase' do
      it_behaves_like 'callback phase'
      
      context 'with a :valid_within option set' do
        let(:args){ ['imasecret', {auth_url: 'http://example.com/login', valid_within: 300}] }
        
        it 'should work if the iat key is within the time window' do
          encoded = JWT.encode({name: 'Ted', email: 'ted@example.com', iat: Time.now.to_i}, 'imasecret')
          get '/auth/jwt/callback?jwt=' + encoded
          expect(last_response.status).to eq(200)
        end
        
        it 'should not work if the iat key is outside the time window' do
          encoded = JWT.encode({name: 'Ted', email: 'ted@example.com', iat: Time.now.to_i + 500}, 'imasecret')
          get '/auth/jwt/callback?jwt=' + encoded
          expect(last_response.status).to eq(302)
        end
        
        it 'should not work if the iat key is missing' do
          encoded = JWT.encode({name: 'Ted', email: 'ted@example.com'}, 'imasecret')
          get '/auth/jwt/callback?jwt=' + encoded
          expect(last_response.status).to eq(302)
        end
      end
    end
  end
end
