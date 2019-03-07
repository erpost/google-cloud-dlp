from google.cloud import dlp_v2
from secrets import get_project, get_key
import os

project_id = get_project()

if os.path.isfile(get_key()):
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = get_key()


def detect_file(project, filename):

    dlp_client = dlp_v2.DlpServiceClient()

    # Prepare info_types by converting the list of strings into a list of
    # dictionaries (protos are also accepted).
    info_types = [{'name': 'ALL_BASIC'}]

    inspect_config = {
        'info_types': info_types,
        'min_likelihood': None,
        'include_quote': True,
        'limits': {'max_findings_per_request': None},
    }

    # Construct the item, containing the file's byte data.
    with open(filename, mode='rb') as f:
        item = {'byte_item': {'type': 5, 'data': f.read()}}

    # Convert the project id into a full resource id.
    parent = dlp_client.project_path(project)

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
        pass


if __name__ == '__main__':
    infile = input('File to inspect: ')
    if len(infile) < 1:
        infile = 'fake_ssn_dob.csv'
    detect_file(project_id, infile)


    # answer = inspect_file(project_id, input_file)
    # print('Value: {}\n'
    #       'InfoType: {}\n'
    #       'Likelihood: {}\n'.format(answer[0], answer[1], answer[2]))
