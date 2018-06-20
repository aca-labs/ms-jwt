require 'omniauth'
require 'jwt'
require 'json'

=begin
Exmaple token
{
  "aud": "66710ccd-b2e4-4b48-9c92-98edc0569d9e",
  "iss": "https://sts.windows.net/a3299bba-ade6-4965-b011-bada8d1d9458/",
  "iat": 1524111517,
  "nbf": 1524111517,
  "exp": 1524115417,
  "aio": "Y2dgYOibsfMdg3xBZeMahtXO4XfrVz2YcVcnJVdC44vjd/S1bboB",
  "amr": [
    "pwd"
  ],
  "family_name": "BUR",
  "given_name": "KIM",
  "ipaddr": "203.217.17.55",
  "name": "B, Kim (CORPORATION)",
  "nonce": "a5d87414-2a71-42be-a354-ca1d9ec8f8dc",
  "oid": "9e40a2f2-416b-4886-8dee-eca4da44b58f",
  "onprem_sid": "S-1-5-21-34999301-1456634306-1590110664-466874",
  "sub": "vhJP4PJcOO2IFM8gG2RPV2Fyo4vvsvlZLfbrsTM23Zo",
  "tid": "a3299bba-ade6-4965-b011-bada8d1d9568",
  "unique_name": "kim@company.com.au",
  "upn": "kim@company.com.au",
  "uti": "vw0JvvvSxE-dX6w7ieUWAB",
  "ver": "1.0"
}
=end

module OmniAuth
  module Strategies
    class JWT
      class ClaimInvalid < StandardError; end

      include OmniAuth::Strategy

      option :uid_claim, 'upn'
      option :required_claims, %w(given_name family_name)
      option :info_map, {"name" => proc { |raw| "#{raw['given_name']} #{raw['family_name']}".titleize }, "email" => "upn"}

      def request_phase
        redirect callback_url
      end

      attr_reader :decoded

      def callback_phase
        id_token = cookies['id_token'] || params['id_token']
        if id_token
          @raw_token = id_token
          parse_token(id_token)
          super
        else
          fail! :invalid_credentials
        end
      rescue ClaimInvalid => e
        fail! :claim_invalid, e
      end

      uid do
        decoded[options.uid_claim]
      end

      extra do
        {:raw_info => decoded, raw_token: @raw_token}
      end

      info do
        options.info_map.inject({}) do |h,(k,v)|
          h[k.to_s] = v.respond_to?(:call) ? v.call(decoded) : decoded[v.to_s]
          h
        end
      end

      private

      def parse_token(data)
        @decoded = ::JWT.decode(data, nil, false)[0]

        (options.required_claims || []).each do |field|
          raise ClaimInvalid.new("Missing required '#{field}' claim.") if !@decoded.key?(field.to_s)
        end
        
        @decoded['token'] = data
      end

      def params
        request.params
      end

      def cookies
        request.cookies
      end
    end

    class Jwt < JWT; end
  end
end
