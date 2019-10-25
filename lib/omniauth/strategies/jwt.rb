require 'omniauth'
require 'jwt'

module OmniAuth
  module Strategies
    class JWT
      class ClaimInvalid < StandardError; end
      
      include OmniAuth::Strategy
      
      args [:secret]
      
      option :secret, nil
      option :algorithm, 'HS256'
      option :uid_claim, 'email'
      option :required_claims, %w(name email)
      option :info_map, {"name" => "name", "email" => "email"}
      option :auth_url, nil
      option :valid_within, nil
      
      def request_phase
        redirect options.auth_url
      end
      
      def decoded
        @decoded ||= ::JWT.decode(request.params['jwt'], options.secret, true, {algorithm: options.algorithm, verify_iat: !!options.valid_within}).reduce(&:merge)


        (options.required_claims || []).each do |field|
          raise ClaimInvalid.new("Missing required '#{field}' claim.") if !@decoded.key?(field.to_s)
        end

        raise ClaimInvalid.new("Missing required 'iat' claim.") if options.valid_within && !@decoded["iat"]

        @decoded
      end
      
      def callback_phase
        super
      rescue ::JWT::ExpiredSignature => e
        fail! :claim_invalid, e
      rescue ::JWT::InvalidIatError => e
        fail! :claim_invalid, e
      rescue ClaimInvalid => e
        fail! :claim_invalid, e
      end
      
      uid{ decoded[options.uid_claim] }
      
      extra do
        {:raw_info => decoded}
      end
      
      info do
        options.info_map.inject({}) do |h,(k,v)|
          h[k.to_s] = decoded[v.to_s]
          h
        end
      end
    end
    
    class Jwt < JWT; end
  end
end
