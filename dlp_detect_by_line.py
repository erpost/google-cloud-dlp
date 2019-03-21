from google.cloud import dlp_v2
from secrets import get_project, get_key
import os

project_id = get_project()

if os.path.isfile(get_key()):
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = get_key()


def detect_line(content):
    dlp_client = dlp_v2.DlpServiceClient()

    # Construct the item to inspect.
    item = {'value': content}

    # The info types to search for in the content. Required.
    info_types = [{'name': 'PERSON_NAME'}]

    # info_types = [{'name': 'PERSON_NAME'}, {'name': 'FIRST_NAME'}, {'name': 'LAST_NAME'},
    #               {'name': 'DATE_OF_BIRTH'},
    #               {'name': 'US_SOCIAL_SECURITY_NUMBER'}]

    # The minimum likelihood to constitute a match. Optional.
    min_likelihood = 'LIKELIHOOD_UNSPECIFIED'

    # The maximum number of findings to report (0 = server maximum). Optional.
    max_findings = 0

    # Whether to include the matching string in the results. Optional.
    include_quote = True

    # Construct the configuration dictionary. Keys which are None may
    # optionally be omitted entirely.
    inspect_config = {
        'info_types': info_types,
        'min_likelihood': min_likelihood,
        'include_quote': include_quote,
        'limits': {'max_findings_per_request': max_findings},
    }

    # Convert the project id into a full resource id.
    parent = dlp_client.project_path(project_id)

    # Call the API.
    response = dlp_client.inspect_content(parent, inspect_config, item)

    # Print out the results.
    if response.result.findings:
        for finding in response.result.findings:
            try:
                value = finding.quote
                info_type = finding.info_type.name
                likelihood = (dlp_v2.types.Finding.DESCRIPTOR.fields_by_name['likelihood']
                              .enum_type.values_by_number[finding.likelihood].name)

                print('Value: {} | Info type: {} | Likelihood: {}'
                      .format(value, info_type, likelihood))

            except AttributeError as err:
                print(err)
    else:
        print('No findings.')


if __name__ == '__main__':
    infile = input('File to inspect (default: fake_ssn_dob.csv): ')
    if len(infile) < 1:
        infile = 'fake_ssn_dob.csv'

    with open(infile) as f:
        for line in f.readlines():
            print('#' * 15)
            print(line)
            detect_line(line)
